from typing import Any

from scanner.aws.models.security_group import SecurityGroupRule


class SecurityGroupNormalizer:
    """
    Converts AWS security-group ingress permissions into
    CloudSentinel's normalized SecurityGroupRule model.
    """

    @staticmethod
    def normalize_ingress_rule(
        permission: dict[str, Any],
    ) -> list[SecurityGroupRule]:
        protocol = permission.get("IpProtocol")

        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")

        normalized_rules: list[SecurityGroupRule] = []

        for ip_range in permission.get("IpRanges", []):
            cidr = ip_range.get("CidrIp")

            if cidr:
                normalized_rules.append(
                    SecurityGroupRule(
                        protocol=protocol,
                        from_port=from_port,
                        to_port=to_port,
                        ipv4_cidr=cidr,
                    )
                )

        for ipv6_range in permission.get("Ipv6Ranges", []):
            cidr = ipv6_range.get("CidrIpv6")

            if cidr:
                normalized_rules.append(
                    SecurityGroupRule(
                        protocol=protocol,
                        from_port=from_port,
                        to_port=to_port,
                        ipv6_cidr=cidr,
                    )
                )

        for group_reference in permission.get(
            "UserIdGroupPairs",
            [],
        ):
            group_id = group_reference.get("GroupId")

            if group_id:
                normalized_rules.append(
                    SecurityGroupRule(
                        protocol=protocol,
                        from_port=from_port,
                        to_port=to_port,
                        source_security_group_id=group_id,
                    )
                )

        return normalized_rules

    @classmethod
    def normalize_security_group(
        cls,
        security_group: dict[str, Any],
    ) -> list[SecurityGroupRule]:
        normalized_rules: list[SecurityGroupRule] = []

        for permission in security_group.get(
            "IpPermissions",
            [],
        ):
            normalized_rules.extend(
                cls.normalize_ingress_rule(permission)
            )

        return normalized_rules
