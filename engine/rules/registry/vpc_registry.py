from engine.rules.aws.vpc.default_security_group import (
    build_default_security_group_finding,
    check_default_security_group,
)
from engine.rules.aws.vpc.default_vpc import (
    build_default_vpc_finding,
    check_default_vpc,
)
from engine.rules.aws.vpc.flow_logs import (
    build_vpc_flow_logs_finding,
    check_vpc_flow_logs,
)
from engine.rules.aws.vpc.orphaned_internet_gateway import (
    build_orphaned_internet_gateway_finding,
    check_orphaned_internet_gateway,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


VPC_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-VPC-001",
            name="default_vpc",
            data_source="vpcs",
            collection_mode="multiple",
            check_arguments=[
                "vpc_id",
                "cidr_block",
                "is_default",
            ],
            check=check_default_vpc,
            build_finding=build_default_vpc_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-VPC-002",
            name="orphaned_internet_gateway",
            data_source="internet_gateways",
            collection_mode="multiple",
            check_arguments=[
                "internet_gateway_id",
                "vpc_id",
                "state",
            ],
            check=check_orphaned_internet_gateway,
            build_finding=build_orphaned_internet_gateway_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-VPC-003",
            name="default_security_group",
            data_source="default_security_groups",
            collection_mode="multiple",
            check_arguments=[
                "group_id",
                "vpc_id",
                "group_name",
                "inbound_rule_count",
                "outbound_rule_count",
            ],
            check=check_default_security_group,
            build_finding=build_default_security_group_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-VPC-004",
            name="vpc_flow_logs",
            data_source="flow_log_coverage",
            collection_mode="multiple",
            check_arguments=[
                "vpc_id",
                "flow_log_count",
                "active_flow_log_count",
                "flow_logging_enabled",
            ],
            check=check_vpc_flow_logs,
            build_finding=build_vpc_flow_logs_finding,
        ),
    ]
)
