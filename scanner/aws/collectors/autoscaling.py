from typing import Any

from scanner.aws.services.autoscaling import AutoScalingService


class AutoScalingDataCollector:
    """Normalize AWS EC2 Auto Scaling data for CloudSentinel rules."""

    def __init__(
        self,
        service: AutoScalingService,
    ):
        self.service = service

        self._groups_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._launch_configurations_cache: (
            dict[str, dict[str, Any]]
            | None
        ) = None

    def _get_groups(self) -> list[dict[str, Any]]:
        if self._groups_cache is None:
            self._groups_cache = (
                self.service.list_auto_scaling_groups()
            )

        return self._groups_cache

    def _get_launch_configurations(
        self,
        names: list[str],
    ) -> dict[str, dict[str, Any]]:
        if self._launch_configurations_cache is not None:
            return self._launch_configurations_cache

        unique_names = sorted(
            {
                name
                for name in names
                if isinstance(name, str) and name
            }
        )

        if not unique_names:
            self._launch_configurations_cache = {}
            return self._launch_configurations_cache

        configurations = (
            self.service.list_launch_configurations(
                unique_names
            )
        )

        self._launch_configurations_cache = {
            configuration["LaunchConfigurationName"]: configuration
            for configuration in configurations
            if isinstance(
                configuration.get("LaunchConfigurationName"),
                str,
            )
            and configuration.get("LaunchConfigurationName")
        }

        return self._launch_configurations_cache

    @staticmethod
    def _normalize_tags(
        tags: Any,
    ) -> dict[str, str]:
        normalized: dict[str, str] = {}

        if not isinstance(tags, list):
            return normalized

        for tag in tags:
            if not isinstance(tag, dict):
                continue

            key = tag.get("Key")
            value = tag.get("Value", "")

            if (
                isinstance(key, str)
                and key
                and not key.startswith("aws:")
            ):
                normalized[key] = str(value)

        return normalized

    @staticmethod
    def _extract_instance_types(
        group: dict[str, Any],
        launch_configuration: dict[str, Any] | None,
    ) -> tuple[list[str], bool]:
        """
        Return explicit instance types and whether the configuration
        uses attribute-based instance requirements.

        AWS Config's autoscaling-multiple-instance-types rule does not
        evaluate attribute-based instance types, so those configurations
        are intentionally treated as unknown rather than non-compliant.
        """
        mixed_policy = group.get(
            "MixedInstancesPolicy"
        )

        if isinstance(mixed_policy, dict):
            launch_template = mixed_policy.get(
                "LaunchTemplate"
            )

            if isinstance(launch_template, dict):
                overrides = launch_template.get(
                    "Overrides",
                    [],
                )

                if isinstance(overrides, list):
                    explicit_types: set[str] = set()
                    uses_requirements = False

                    for override in overrides:
                        if not isinstance(override, dict):
                            continue

                        instance_type = override.get(
                            "InstanceType"
                        )

                        if (
                            isinstance(instance_type, str)
                            and instance_type
                        ):
                            explicit_types.add(
                                instance_type
                            )

                        if isinstance(
                            override.get("InstanceRequirements"),
                            dict,
                        ):
                            uses_requirements = True

                    return (
                        sorted(explicit_types),
                        uses_requirements,
                    )

            return [], False

        launch_configuration_name = group.get(
            "LaunchConfigurationName"
        )

        if (
            isinstance(
                launch_configuration_name,
                str,
            )
            and launch_configuration
        ):
            instance_type = launch_configuration.get(
                "InstanceType"
            )

            if (
                isinstance(instance_type, str)
                and instance_type
            ):
                return [instance_type], False

        # A normal LaunchTemplate-backed ASG without a mixed
        # instances policy uses one launch template configuration.
        if isinstance(
            group.get("LaunchTemplate"),
            dict,
        ):
            return ["__single_launch_template__"], False

        return [], False

    def collect_auto_scaling_groups(
        self,
    ) -> list[dict[str, Any]]:
        groups = self._get_groups()

        launch_configuration_names = [
            group.get("LaunchConfigurationName")
            for group in groups
            if isinstance(group, dict)
            and isinstance(
                group.get("LaunchConfigurationName"),
                str,
            )
            and group.get("LaunchConfigurationName")
        ]

        launch_configurations = (
            self._get_launch_configurations(
                launch_configuration_names
            )
        )

        normalized: list[dict[str, Any]] = []

        for group in groups:
            name = group.get(
                "AutoScalingGroupName"
            )

            if not isinstance(name, str) or not name:
                continue

            arn = group.get(
                "AutoScalingGroupARN"
            )

            if not isinstance(arn, str) or not arn:
                arn = None

            availability_zones = group.get(
                "AvailabilityZones",
                [],
            )

            if not isinstance(
                availability_zones,
                list,
            ):
                availability_zones = []

            availability_zones = sorted(
                {
                    zone
                    for zone in availability_zones
                    if isinstance(zone, str)
                    and zone
                }
            )

            load_balancers = group.get(
                "LoadBalancerNames",
                [],
            )

            if not isinstance(
                load_balancers,
                list,
            ):
                load_balancers = []

            target_groups = group.get(
                "TargetGroupARNs",
                [],
            )

            if not isinstance(
                target_groups,
                list,
            ):
                target_groups = []

            has_load_balancer = bool(
                load_balancers or target_groups
            )

            tags = self._normalize_tags(
                group.get("Tags", [])
            )

            launch_configuration_name = group.get(
                "LaunchConfigurationName"
            )

            launch_configuration = None

            if isinstance(
                launch_configuration_name,
                str,
            ):
                launch_configuration = (
                    launch_configurations.get(
                        launch_configuration_name
                    )
                )

            instance_types, uses_requirements = (
                self._extract_instance_types(
                    group,
                    launch_configuration,
                )
            )

            mixed_policy = group.get(
                "MixedInstancesPolicy"
            )

            has_launch_template = isinstance(
                group.get("LaunchTemplate"),
                dict,
            )

            if isinstance(mixed_policy, dict):
                mixed_launch_template = (
                    mixed_policy.get("LaunchTemplate")
                )

                has_launch_template = (
                    has_launch_template
                    or isinstance(
                        mixed_launch_template,
                        dict,
                    )
                )

            health_check_type = group.get(
                "HealthCheckType"
            )

            if not isinstance(
                health_check_type,
                str,
            ):
                health_check_type = None

            metadata_options = None
            associate_public_ip = None
            launch_config_data_available = (
                launch_configuration is not None
            )

            if launch_configuration:
                metadata_options = (
                    launch_configuration.get(
                        "MetadataOptions"
                    )
                )

                if not isinstance(
                    metadata_options,
                    dict,
                ):
                    metadata_options = None

                associate_public_ip = (
                    launch_configuration.get(
                        "AssociatePublicIpAddress"
                    )
                )

                if not isinstance(
                    associate_public_ip,
                    bool,
                ):
                    associate_public_ip = None

            metadata_http_tokens = None

            if isinstance(
                metadata_options,
                dict,
            ):
                metadata_http_tokens = (
                    metadata_options.get(
                        "HttpTokens"
                    )
                )

                if not isinstance(
                    metadata_http_tokens,
                    str,
                ):
                    metadata_http_tokens = None

            normalized.append(
                {
                    "group_name": name,
                    "group_arn": arn,
                    "has_load_balancer": has_load_balancer,
                    "health_check_type": health_check_type,
                    "availability_zones": availability_zones,
                    "availability_zone_count": len(
                        availability_zones
                    ),
                    "has_launch_template": (
                        has_launch_template
                    ),
                    "launch_configuration_name": (
                        launch_configuration_name
                        if isinstance(
                            launch_configuration_name,
                            str,
                        )
                        else None
                    ),
                    "launch_configuration_data_available": (
                        launch_config_data_available
                    ),
                    "metadata_http_tokens": (
                        metadata_http_tokens
                    ),
                    "associate_public_ip_address": (
                        associate_public_ip
                    ),
                    "instance_types": instance_types,
                    "instance_type_count": len(
                        instance_types
                    ),
                    "instance_type_data_available": (
                        bool(instance_types)
                    ),
                    "uses_attribute_based_instance_types": (
                        uses_requirements
                    ),
                    "tags": tags,
                    "has_non_system_tags": bool(tags),
                }
            )

        return normalized
