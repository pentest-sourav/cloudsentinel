from typing import Any

from scanner.aws.services.security_groups import SecurityGroupService


class SecurityGroupDataCollector:
    """
    Normalizes AWS Security Group configuration data
    for security rules.
    """

    def __init__(self, service: SecurityGroupService):
        self.service = service
        self._security_groups_cache: list[dict[str, Any]] | None = None
        self._network_interfaces_cache: list[dict[str, Any]] | None = None

    def _get_security_groups(self) -> list[dict[str, Any]]:
        if self._security_groups_cache is None:
            self._security_groups_cache = (
                self.service.describe_security_groups()
            )

        return self._security_groups_cache

    def _get_network_interfaces(self) -> list[dict[str, Any]]:
        if self._network_interfaces_cache is None:
            self._network_interfaces_cache = (
                self.service.describe_network_interfaces()
            )

        return self._network_interfaces_cache

    def collect_security_groups(self) -> list[dict[str, Any]]:
        normalized = []

        for group in self._get_security_groups():
            group_id = group.get("GroupId")

            if not group_id:
                continue

            normalized.append(
                {
                    "group_id": group_id,
                    "group_name": group.get("GroupName"),
                    "description": group.get("Description"),
                    "vpc_id": group.get("VpcId"),
                    "is_default": group.get("GroupName") == "default",
                    "inbound_rules": group.get("IpPermissions", []),
                    "outbound_rules": group.get(
                        "IpPermissionsEgress",
                        [],
                    ),
                }
            )

        return normalized

    def collect_security_group_inventory(self) -> list[dict[str, Any]]:
        """
        Return Security Group inventory including ENI usage.

        Security Groups attached to EC2 instances are represented
        through the instance's Elastic Network Interface.
        """
        security_groups = self.collect_security_groups()

        attachment_counts: dict[str, int] = {}

        for network_interface in self._get_network_interfaces():
            seen_group_ids: set[str] = set()

            for group in network_interface.get("Groups", []):
                group_id = group.get("GroupId")

                if not group_id or group_id in seen_group_ids:
                    continue

                seen_group_ids.add(group_id)
                attachment_counts[group_id] = (
                    attachment_counts.get(group_id, 0) + 1
                )

        inventory = []

        for security_group in security_groups:
            group_id = security_group["group_id"]

            inventory.append(
                {
                    "group_id": group_id,
                    "group_name": security_group["group_name"],
                    "is_default": security_group["is_default"],
                    "attached_eni_count": attachment_counts.get(
                        group_id,
                        0,
                    ),
                }
            )

        return inventory
