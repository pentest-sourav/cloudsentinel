from typing import Any

from scanner.aws.services.ec2 import EC2Service


class EC2DataCollector:
    """
    Collects and normalizes EC2 data required by
    CloudSentinel security rules.

    This layer does not make security decisions.
    """

    def __init__(self, service: EC2Service):
        self.service = service

        self._instances_cache: list[dict[str, Any]] | None = None
        self._security_groups_cache: list[dict[str, Any]] | None = None
        self._ebs_default_encryption_cache: bool | None = None
        self._addresses_cache: list[dict[str, Any]] | None = None
        self._launch_templates_cache: (
            list[dict[str, Any]] | None
        ) = None
        self._snapshot_block_public_access_cache: (
            dict[str, Any] | None
        ) = None

    def _get_instances(self) -> list[dict[str, Any]]:
        if self._instances_cache is None:
            self._instances_cache = self.service.describe_instances()

        return self._instances_cache

    def _get_security_groups(self) -> list[dict[str, Any]]:
        if self._security_groups_cache is None:
            self._security_groups_cache = (
                self.service.describe_all_security_groups()
            )

        return self._security_groups_cache

    def collect_instances(self) -> list[dict[str, Any]]:
        instances = self._get_instances()

        collected_instances: list[dict[str, Any]] = []

        for instance in instances:
            security_groups = instance.get(
                "SecurityGroups",
                [],
            )

            security_group_ids = [
                group["GroupId"]
                for group in security_groups
                if "GroupId" in group
            ]

            collected_instances.append(
                {
                    "instance_id": instance.get("InstanceId"),
                    "instance_state": (
                        instance.get(
                            "State",
                            {},
                        ).get("Name")
                    ),
                    "security_group_ids": security_group_ids,
                    "public_ip": instance.get(
                        "PublicIpAddress"
                    ),
                    "private_ip": instance.get(
                        "PrivateIpAddress"
                    ),
                    "metadata_http_tokens": (
                        instance.get(
                            "MetadataOptions",
                            {},
                        ).get("HttpTokens")
                    ),
                }
            )

        return collected_instances

    def collect_extended_instances(self) -> list[dict[str, Any]]:
        instances = self._get_instances()

        collected_instances: list[dict[str, Any]] = []

        for instance in instances:
            network_interfaces = instance.get(
                "NetworkInterfaces",
                [],
            )

            collected_instances.append(
                {
                    "instance_id": instance.get("InstanceId"),
                    "instance_state": (
                        instance.get(
                            "State",
                            {},
                        ).get("Name")
                    ),
                    "network_interface_count": len(
                        network_interfaces
                    ),
                    "virtualization_type": instance.get(
                        "VirtualizationType"
                    ),
                    "launch_time": instance.get(
                        "LaunchTime"
                    ),
                    "state_transition_reason": instance.get(
                        "StateTransitionReason"
                    ),
                }
            )

        return collected_instances

    def collect_ebs_volumes(
        self,
    ) -> list[dict[str, Any]]:
        instances = self._get_instances()

        instance_volume_map: list[dict[str, str]] = []
        volume_ids: set[str] = set()

        for instance in instances:
            instance_id = instance.get("InstanceId")

            if not instance_id:
                continue

            for mapping in instance.get(
                "BlockDeviceMappings",
                [],
            ):
                ebs = mapping.get("Ebs", {})
                volume_id = ebs.get("VolumeId")

                if not volume_id:
                    continue

                instance_volume_map.append(
                    {
                        "instance_id": instance_id,
                        "volume_id": volume_id,
                    }
                )

                volume_ids.add(volume_id)

        if not volume_ids:
            return []

        volumes = self.service.describe_volumes(
            sorted(volume_ids)
        )

        encryption_by_volume_id = {
            volume.get("VolumeId"): volume.get("Encrypted")
            for volume in volumes
            if volume.get("VolumeId")
        }

        collected_volumes: list[dict[str, Any]] = []

        for mapping in instance_volume_map:
            volume_id = mapping["volume_id"]

            if volume_id not in encryption_by_volume_id:
                continue

            collected_volumes.append(
                {
                    "instance_id": mapping["instance_id"],
                    "volume_id": volume_id,
                    "encrypted": encryption_by_volume_id[
                        volume_id
                    ],
                }
            )

        return collected_volumes

    def collect_security_groups(
        self,
    ) -> list[dict[str, Any]]:
        return self._get_security_groups()

    def collect_snapshots(
        self,
    ) -> list[dict[str, Any]]:
        snapshots = self.service.describe_snapshots()

        collected_snapshots: list[dict[str, Any]] = []

        for snapshot in snapshots:
            snapshot_id = snapshot.get("SnapshotId")

            if not snapshot_id:
                continue

            collected_snapshots.append(
                {
                    "snapshot_id": snapshot_id,
                    "volume_id": snapshot.get("VolumeId"),
                    "state": snapshot.get("State"),
                    "public": snapshot.get("Public", False),
                }
            )

        return collected_snapshots

    def collect_ebs_default_encryption(
        self,
    ) -> list[dict[str, Any]]:
        if self._ebs_default_encryption_cache is None:
            self._ebs_default_encryption_cache = (
                self.service.get_ebs_encryption_by_default()
            )

        return [
            {
                "ebs_encryption_by_default": (
                    self._ebs_default_encryption_cache
                )
            }
        ]

    def collect_elastic_ips(
        self,
    ) -> list[dict[str, Any]]:
        if self._addresses_cache is None:
            addresses = self.service.describe_addresses()

            if not isinstance(addresses, list):
                self._addresses_cache = []
            else:
                self._addresses_cache = addresses

        collected_addresses: list[dict[str, Any]] = []

        for address in self._addresses_cache:
            allocation_id = address.get("AllocationId")

            if not allocation_id:
                continue

            instance_id = address.get("InstanceId")
            network_interface_id = address.get(
                "NetworkInterfaceId"
            )

            collected_addresses.append(
                {
                    "allocation_id": allocation_id,
                    "public_ip": address.get("PublicIp"),
                    "instance_id": instance_id,
                    "network_interface_id": (
                        network_interface_id
                    ),
                    "associated": bool(
                        instance_id
                        or network_interface_id
                    ),
                }
            )

        return collected_addresses

    def collect_launch_template_ebs_encryption(
        self,
    ) -> list[dict[str, Any]]:
        """
        Collect explicitly configured EBS encryption settings from
        the default version of every EC2 launch template.

        A missing Encrypted property is not treated as False.
        """

        if self._launch_templates_cache is None:
            launch_templates = (
                self.service.describe_launch_templates()
            )

            if not isinstance(launch_templates, list):
                self._launch_templates_cache = []
            else:
                self._launch_templates_cache = launch_templates

        collected: list[dict[str, Any]] = []

        for launch_template in self._launch_templates_cache:
            if not isinstance(launch_template, dict):
                continue

            launch_template_id = launch_template.get(
                "LaunchTemplateId"
            )

            if not launch_template_id:
                continue

            versions = (
                self.service
                .describe_default_launch_template_versions(
                    launch_template_id
                )
            )

            if not isinstance(versions, list):
                continue

            for version in versions:
                if not isinstance(version, dict):
                    continue

                launch_template_data = version.get(
                    "LaunchTemplateData",
                    {},
                )

                if not isinstance(
                    launch_template_data,
                    dict,
                ):
                    continue

                block_device_mappings = (
                    launch_template_data.get(
                        "BlockDeviceMappings",
                        [],
                    )
                )

                if not isinstance(
                    block_device_mappings,
                    list,
                ):
                    continue

                for mapping in block_device_mappings:
                    if not isinstance(mapping, dict):
                        continue

                    ebs = mapping.get("Ebs")

                    if not isinstance(ebs, dict):
                        continue

                    if "Encrypted" not in ebs:
                        continue

                    encrypted = ebs.get("Encrypted")

                    if not isinstance(encrypted, bool):
                        continue

                    collected.append(
                        {
                            "launch_template_id": (
                                launch_template_id
                            ),
                            "launch_template_name": (
                                launch_template.get(
                                    "LaunchTemplateName"
                                )
                            ),
                            "version_number": (
                                version.get("VersionNumber")
                            ),
                            "device_name": (
                                mapping.get("DeviceName")
                            ),
                            "encrypted": encrypted,
                        }
                    )

        return collected

    def collect_snapshot_block_public_access(
        self,
    ) -> list[dict[str, Any]]:
        if self._snapshot_block_public_access_cache is None:
            state = (
                self.service
                .get_snapshot_block_public_access_state()
            )

            # A non-dict response means the service response was not
            # usable. Do not manufacture a non-compliant finding from
            # an unconfigured/mock/invalid response.
            if not isinstance(state, dict):
                return []

            self._snapshot_block_public_access_cache = state

        return [
            {
                "state": (
                    self._snapshot_block_public_access_cache.get(
                        "state"
                    )
                ),
                "managed_by": (
                    self._snapshot_block_public_access_cache.get(
                        "managed_by"
                    )
                ),
            }
        ]
