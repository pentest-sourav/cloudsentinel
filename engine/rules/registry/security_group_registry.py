from engine.rules.aws.security_groups.authorized_ports import (
    build_authorized_ports_finding,
    check_authorized_ports,
)
from engine.rules.aws.security_groups.high_risk_ports import (
    build_high_risk_ports_finding,
    check_high_risk_ports,
)
from engine.rules.aws.security_groups.remote_admin_ipv4 import (
    build_remote_admin_ipv4_finding,
    check_remote_admin_ipv4,
)
from engine.rules.aws.security_groups.remote_admin_ipv6 import (
    build_remote_admin_ipv6_finding,
    check_remote_admin_ipv6,
)
from engine.rules.aws.security_groups.unrestricted_inbound import (
    build_unrestricted_inbound_finding,
    check_unrestricted_inbound,
)
from engine.rules.aws.security_groups.unused import (
    build_unused_security_group_finding,
    check_unused_security_group,
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
        RuleDefinition(
            rule_id="CS-AWS-SG-002",
            name="authorized_ports",
            data_source="security_groups",
            collection_mode="multiple",
            check_arguments=[
                "group_id",
                "group_name",
                "inbound_rule",
            ],
            check=check_authorized_ports,
            build_finding=build_authorized_ports_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SG-003",
            name="high_risk_ports",
            data_source="security_groups",
            collection_mode="multiple",
            check_arguments=[
                "group_id",
                "group_name",
                "inbound_rule",
            ],
            check=check_high_risk_ports,
            build_finding=build_high_risk_ports_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SG-004",
            name="unused_security_group",
            data_source="security_group_inventory",
            collection_mode="multiple",
            check_arguments=[
                "group_id",
                "group_name",
                "attached_eni_count",
                "is_default",
            ],
            check=check_unused_security_group,
            build_finding=build_unused_security_group_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SG-005",
            name="remote_admin_ipv4",
            data_source="security_groups",
            collection_mode="multiple",
            check_arguments=[
                "group_id",
                "group_name",
                "inbound_rule",
            ],
            check=check_remote_admin_ipv4,
            build_finding=build_remote_admin_ipv4_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SG-006",
            name="remote_admin_ipv6",
            data_source="security_groups",
            collection_mode="multiple",
            check_arguments=[
                "group_id",
                "group_name",
                "inbound_rule",
            ],
            check=check_remote_admin_ipv6,
            build_finding=build_remote_admin_ipv6_finding,
        ),
    ]
)
