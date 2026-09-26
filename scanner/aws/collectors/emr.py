import json
from typing import Any

from scanner.aws.services.emr import EMRService


class EMRDataCollector:
    """
    Normalize Amazon EMR API data for CloudSentinel rules.

    API responses are collected once and cached for the lifetime
    of the collector.
    """

    def __init__(self, service: EMRService):
        self.service = service

        self._clusters_cache: list[dict[str, Any]] | None = None
        self._master_instances_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        self._security_configurations_cache: (
            list[dict[str, Any]] | None
        ) = None

        self._security_configuration_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}

        self._block_public_access_cache: (
            dict[str, Any] | None
        ) = None

    def _get_clusters(self) -> list[dict[str, Any]]:
        if self._clusters_cache is None:
            self._clusters_cache = (
                self.service.list_clusters()
            )

        return self._clusters_cache

    def _get_master_instances(
        self,
        cluster_id: str,
    ) -> list[dict[str, Any]]:
        if cluster_id not in self._master_instances_cache:
            self._master_instances_cache[
                cluster_id
            ] = self.service.list_master_instances(
                cluster_id
            )

        return self._master_instances_cache[
            cluster_id
        ]

    def _get_security_configurations(
        self,
    ) -> list[dict[str, Any]]:
        if self._security_configurations_cache is None:
            self._security_configurations_cache = (
                self.service.list_security_configurations()
            )

        return self._security_configurations_cache

    def _get_security_configuration_details(
        self,
        name: str,
    ) -> dict[str, Any]:
        if (
            name
            not in self._security_configuration_details_cache
        ):
            self._security_configuration_details_cache[
                name
            ] = self.service.get_security_configuration(
                name
            )

        return self._security_configuration_details_cache[
            name
        ]

    def _get_block_public_access_configuration(
        self,
    ) -> dict[str, Any]:
        if self._block_public_access_cache is None:
            self._block_public_access_cache = (
                self.service
                .get_block_public_access_configuration()
            )

        return self._block_public_access_cache

    @staticmethod
    def _extract_security_configuration(
        response: dict[str, Any],
    ) -> dict[str, Any]:
        raw_configuration = response.get(
            "SecurityConfiguration"
        )

        if not raw_configuration:
            return {}

        if isinstance(raw_configuration, dict):
            return raw_configuration

        if not isinstance(raw_configuration, str):
            return {}

        try:
            parsed = json.loads(raw_configuration)
        except (TypeError, ValueError):
            return {}

        if not isinstance(parsed, dict):
            return {}

        return parsed

    @staticmethod
    def _extract_encryption_flags(
        configuration: dict[str, Any],
    ) -> tuple[bool | None, bool | None]:
        encryption = configuration.get(
            "EncryptionConfiguration"
        )

        if not isinstance(encryption, dict):
            return None, None

        at_rest = encryption.get(
            "EnableAtRestEncryption"
        )
        in_transit = encryption.get(
            "EnableInTransitEncryption"
        )

        return (
            at_rest
            if isinstance(at_rest, bool)
            else None,
            in_transit
            if isinstance(in_transit, bool)
            else None,
        )

    @staticmethod
    def _is_port_22_range(
        value: Any,
    ) -> bool:
        if not isinstance(value, str):
            return False

        value = value.strip()

        if value == "22":
            return True

        if value == "22-22":
            return True

        return False

    def collect_clusters(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for cluster in self._get_clusters():
            cluster_id = cluster.get("Id")

            if not cluster_id:
                continue

            master_instances = self._get_master_instances(
                cluster_id
            )

            public_ip_values = [
                instance.get("PublicIpAddress")
                for instance in master_instances
                if instance.get("PublicIpAddress")
            ]

            has_public_ip: bool | None

            if not master_instances:
                has_public_ip = None
            else:
                has_public_ip = bool(public_ip_values)

            normalized.append(
                {
                    "cluster_id": cluster_id,
                    "cluster_arn": cluster.get("ClusterArn"),
                    "cluster_name": cluster.get("Name"),
                    "cluster_status": (
                        cluster.get("Status", {})
                        .get("State")
                    ),
                    "master_public_ip": (
                        public_ip_values[0]
                        if public_ip_values
                        else None
                    ),
                    "master_has_public_ip": has_public_ip,
                    "master_instance_count": len(
                        master_instances
                    ),
                }
            )

        return normalized

    def collect_security_configurations(
        self,
    ) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for item in self._get_security_configurations():
            name = item.get("Name")

            if not name:
                continue

            response = (
                self._get_security_configuration_details(
                    name
                )
            )

            configuration = (
                self._extract_security_configuration(
                    response
                )
            )

            (
                at_rest_encryption,
                in_transit_encryption,
            ) = self._extract_encryption_flags(
                configuration
            )

            normalized.append(
                {
                    "security_configuration_name": name,
                    "security_configuration_arn": (
                        item.get("Arn")
                        or response.get("SecurityConfigurationArn")
                    ),
                    "enable_at_rest_encryption": (
                        at_rest_encryption
                    ),
                    "enable_in_transit_encryption": (
                        in_transit_encryption
                    ),
                }
            )

        return normalized

    def collect_block_public_access(
        self,
    ) -> list[dict[str, Any]]:
        configuration = (
            self._get_block_public_access_configuration()
        )

        if not configuration:
            return []

        block_public_security_group_rules = (
            configuration.get(
                "BlockPublicSecurityGroupRules"
            )
        )

        permitted_ranges = configuration.get(
            "PermittedPublicSecurityGroupRuleRanges"
        )

        if permitted_ranges is None:
            permitted_ranges = []

        if not isinstance(permitted_ranges, list):
            permitted_ranges = []

        has_unsafe_exception = any(
            not self._is_port_22_range(value)
            for value in permitted_ranges
        )

        return [
            {
                "block_public_security_group_rules": (
                    block_public_security_group_rules
                    if isinstance(
                        block_public_security_group_rules,
                        bool,
                    )
                    else None
                ),
                "permitted_public_security_group_rule_ranges": (
                    permitted_ranges
                ),
                "has_unsafe_public_access_exception": (
                    has_unsafe_exception
                ),
            }
        ]
