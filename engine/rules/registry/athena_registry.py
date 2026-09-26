from engine.rules.aws.athena.protection import (
    build_athena_data_catalog_tags_finding,
    build_athena_workgroup_logging_finding,
    build_athena_workgroup_tags_finding,
    check_athena_data_catalog_tags,
    check_athena_workgroup_logging,
    check_athena_workgroup_tags,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


ATHENA_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-ATHENA-002",
            name="athena_data_catalog_tags",
            data_source="athena_data_catalogs",
            collection_mode="multiple",
            check_arguments=[
                "catalog_name",
                "catalog_arn",
                "tag_data_available",
                "has_non_system_tags",
            ],
            check=check_athena_data_catalog_tags,
            build_finding=(
                build_athena_data_catalog_tags_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-ATHENA-003",
            name="athena_workgroup_tags",
            data_source="athena_workgroups",
            collection_mode="multiple",
            check_arguments=[
                "workgroup_name",
                "workgroup_arn",
                "tag_data_available",
                "has_non_system_tags",
            ],
            check=check_athena_workgroup_tags,
            build_finding=(
                build_athena_workgroup_tags_finding
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-ATHENA-004",
            name="athena_workgroup_logging",
            data_source="athena_workgroups",
            collection_mode="multiple",
            check_arguments=[
                "workgroup_name",
                "publish_cloudwatch_metrics_enabled",
            ],
            check=check_athena_workgroup_logging,
            build_finding=(
                build_athena_workgroup_logging_finding
            ),
        ),
    ]
)
