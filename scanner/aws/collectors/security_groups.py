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

    def _get_security_groups(self) -> list[dict[str, Any]]:
        if self._security_groups_cache is None:
            self._security_groups_cache = (
                self.service.describe_security_groups()
            )

        return self._security_groups_cache

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
