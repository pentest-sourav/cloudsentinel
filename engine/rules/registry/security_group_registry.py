from engine.rules.aws.security_groups.unrestricted_inbound import (
    build_unrestricted_inbound_finding,
    check_unrestricted_inbound,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


SECURITY_GROUP_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-SG-001",
            name="unrestricted_inbound",
            data_source="security_groups",
            collection_mode="multiple",
            check_arguments=[
                "group_id",
                "group_name",
                "inbound_rule",
            ],
            check=check_unrestricted_inbound,
            build_finding=build_unrestricted_inbound_finding,
        ),
    ]
)
