from engine.rules.aws.appsync.protection import (
    build_appsync_api_key_authentication_finding,
    build_appsync_field_logging_finding,
    build_appsync_tags_finding,
    check_appsync_api_key_authentication,
    check_appsync_field_logging,
    check_appsync_tags,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


APPSYNC_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-APPSYNC-002",
            name="appsync_field_logging",
            data_source="appsync_graphql_apis",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "field_log_level",
            ],
            check=check_appsync_field_logging,
            build_finding=(
                build_appsync_field_logging_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-APPSYNC-004",
            name="appsync_graphql_api_tags",
            data_source="appsync_graphql_apis",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "has_non_system_tags",
            ],
            check=check_appsync_tags,
            build_finding=build_appsync_tags_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-APPSYNC-005",
            name="appsync_api_key_authentication",
            data_source="appsync_graphql_apis",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "authentication_type",
                "additional_authentication_types",
            ],
            check=check_appsync_api_key_authentication,
            build_finding=(
                build_appsync_api_key_authentication_finding
            ),
        ),
    ]
)
