from scanner.aws.collectors.security_groups import (
    SecurityGroupDataCollector,
)


def collect_security_groups(
    collector: SecurityGroupDataCollector,
) -> list[dict]:
    security_groups = collector.collect_security_groups()

    normalized_rules = []

    for security_group in security_groups:
        for inbound_rule in security_group.get("inbound_rules", []):
            normalized_rules.append(
                {
                    "group_id": security_group["group_id"],
                    "group_name": security_group["group_name"],
                    "inbound_rule": inbound_rule,
                }
            )

    return normalized_rules


SECURITY_GROUP_DATA_SOURCE_HANDLERS = {
    "security_groups": collect_security_groups,
}
