from engine.rules.aws.detective.controls import (
    build_detective_graph_tags_finding,
    check_detective_graph_tags,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


DETECTIVE_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-DETECTIVE-001",
            name="detective_graph_tags",
            data_source="graphs",
            collection_mode="multiple",
            check_arguments=[
                "resource_name",
                "resource_arn",
                "resource_type",
                "tag_data_available",
                "has_non_system_tags",
                "tags",
            ],
            parameters={"required_tag_keys": []},
            check=check_detective_graph_tags,
            build_finding=(
                build_detective_graph_tags_finding
            ),
        ),
    ]
)
