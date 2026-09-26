from engine.rules.aws.appflow.controls import (
    build_appflow_flow_tags_finding,
    check_appflow_flow_tags,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


APPFLOW_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-APPFLOW-001",
            name="appflow_flow_tags",
            data_source="appflow_flows",
            collection_mode="multiple",
            check_arguments=[
                "flow_name",
                "flow_arn",
                "tag_data_available",
                "has_non_system_tags",
            ],
            check=check_appflow_flow_tags,
            build_finding=build_appflow_flow_tags_finding,
        ),
    ]
)
