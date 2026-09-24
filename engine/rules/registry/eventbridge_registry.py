from engine.rules.aws.eventbridge.global_endpoint_replication import (
    build_eventbridge_global_endpoint_replication_finding,
    check_eventbridge_global_endpoint_replication,
)
from engine.rules.aws.eventbridge.resource_policy import (
    build_eventbridge_resource_policy_finding,
    check_eventbridge_resource_policy,
)
from engine.rules.aws.eventbridge.tagging import (
    build_eventbridge_tagging_finding,
    check_eventbridge_tagging,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


EVENTBRIDGE_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-EVENTBRIDGE-002",
            name="eventbridge_tagging",
            data_source="eventbridge_event_buses",
            collection_mode="multiple",
            check_arguments=[
                "event_bus_arn",
                "tags",
            ],
            check=check_eventbridge_tagging,
            build_finding=build_eventbridge_tagging_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-EVENTBRIDGE-003",
            name="eventbridge_resource_policy",
            data_source="eventbridge_event_buses",
            collection_mode="multiple",
            check_arguments=[
                "event_bus_arn",
                "event_bus_name",
                "event_source_name",
                "policy",
            ],
            check=check_eventbridge_resource_policy,
            build_finding=(
                build_eventbridge_resource_policy_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-EVENTBRIDGE-004",
            name="eventbridge_global_endpoint_replication",
            data_source="eventbridge_global_endpoints",
            collection_mode="multiple",
            check_arguments=[
                "endpoint_arn",
                "replication_config",
            ],
            check=(
                check_eventbridge_global_endpoint_replication
            ),
            build_finding=(
                build_eventbridge_global_endpoint_replication_finding
            ),
        ),
    ]
)
