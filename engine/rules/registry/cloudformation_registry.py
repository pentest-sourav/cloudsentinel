from engine.rules.aws.cloudformation.controls import (
    build_cloudformation_service_role_finding,
    build_cloudformation_stack_tags_finding,
    build_cloudformation_termination_protection_finding,
    check_cloudformation_service_role,
    check_cloudformation_stack_tags,
    check_cloudformation_termination_protection,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


CLOUDFORMATION_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-CLOUDFORMATION-002",
            name="cloudformation_stack_tags",
            data_source="cloudformation_stacks",
            collection_mode="multiple",
            check_arguments=[
                "stack_name",
                "stack_id",
                "tag_data_available",
                "has_non_system_tags",
            ],
            check=check_cloudformation_stack_tags,
            build_finding=build_cloudformation_stack_tags_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDFORMATION-003",
            name="cloudformation_termination_protection",
            data_source="cloudformation_stacks",
            collection_mode="multiple",
            check_arguments=[
                "stack_name",
                "stack_id",
                "termination_protection_enabled",
            ],
            check=check_cloudformation_termination_protection,
            build_finding=(
                build_cloudformation_termination_protection_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDFORMATION-004",
            name="cloudformation_service_role",
            data_source="cloudformation_stacks",
            collection_mode="multiple",
            check_arguments=[
                "stack_name",
                "stack_id",
                "role_arn",
            ],
            check=check_cloudformation_service_role,
            build_finding=build_cloudformation_service_role_finding,
        ),
    ]
)
