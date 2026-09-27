from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.route_tables.default_route import (
    build_default_route_finding,
    check_default_route,
)
from engine.rules.aws.route_tables.tagging import (
    build_route_table_tagging_finding,
    check_route_table_tagging,
)


ROUTE_TABLE_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-RT-001",
            name="active_default_route_to_internet_gateway",
            data_source="routes",
            collection_mode="multiple",
            check_arguments=[
                "route_table_id",
                "vpc_id",
                "route",
            ],
            check=check_default_route,
            build_finding=build_default_route_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-RT-002",
            name="untagged_route_table",
            data_source="route_table_inventory",
            collection_mode="multiple",
            check_arguments=[
                "route_table_id",
                "vpc_id",
                "tags",
            ],
            check=check_route_table_tagging,
            build_finding=build_route_table_tagging_finding,
        ),
    ]
)
