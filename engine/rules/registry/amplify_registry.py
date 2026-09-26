from engine.rules.aws.amplify.controls import (
    build_amplify_app_tags_finding,
    build_amplify_branch_tags_finding,
    check_amplify_app_tags,
    check_amplify_branch_tags,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


AMPLIFY_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-AMPLIFY-001",
            name="amplify_app_tags",
            data_source="amplify_apps",
            collection_mode="multiple",
            check_arguments=[
                "app_name",
                "app_arn",
                "tag_data_available",
                "has_non_system_tags",
            ],
            check=check_amplify_app_tags,
            build_finding=build_amplify_app_tags_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-AMPLIFY-002",
            name="amplify_branch_tags",
            data_source="amplify_branches",
            collection_mode="multiple",
            check_arguments=[
                "branch_name",
                "branch_arn",
                "tag_data_available",
                "has_non_system_tags",
            ],
            check=check_amplify_branch_tags,
            build_finding=build_amplify_branch_tags_finding,
        ),
    ]
)
