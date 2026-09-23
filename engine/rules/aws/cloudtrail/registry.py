from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry

from engine.rules.aws.cloudtrail.logging import (
    build_cloudtrail_logging_finding,
    check_cloudtrail_logging,
)

from engine.rules.aws.cloudtrail.no_trail import (
    build_cloudtrail_no_trail_finding,
    check_cloudtrail_no_trail,
)

from engine.rules.aws.cloudtrail.log_file_validation import (
    build_cloudtrail_log_file_validation_finding,
    check_cloudtrail_log_file_validation,
)

from engine.rules.aws.cloudtrail.multi_region import (
    build_cloudtrail_multi_region_finding,
    check_cloudtrail_multi_region,
)

from engine.rules.aws.cloudtrail.global_service_events import (
    build_cloudtrail_global_service_events_finding,
    check_cloudtrail_global_service_events,
)

from engine.rules.aws.cloudtrail.encryption import (
    build_cloudtrail_encryption_finding,
    check_cloudtrail_encryption,
)

from engine.rules.aws.cloudtrail.management_events import (
    build_cloudtrail_management_events_finding,
    check_cloudtrail_management_events,
)

from engine.rules.aws.cloudtrail.cloudwatch_logs import (
    build_cloudtrail_cloudwatch_logs_finding,
    check_cloudtrail_cloudwatch_logs,
)


from engine.rules.aws.cloudtrail.tagging import (
    build_cloudtrail_tagging_finding,
    check_cloudtrail_tagging,
)

CLOUDTRAIL_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-CT-001",
            name="cloudtrail_logging_enabled",
            data_source="cloudtrail_trails",
            collection_mode="multiple",
            check_arguments=[
                "trail_arn",
                "name",
                "is_logging",
            ],
            check=check_cloudtrail_logging,
            build_finding=build_cloudtrail_logging_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CT-002",
            name="cloudtrail_trail_configured",
            data_source="cloudtrail_account",
            collection_mode="single",
            check_arguments=[
                "trail_count",
            ],
            check=check_cloudtrail_no_trail,
            build_finding=build_cloudtrail_no_trail_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CT-003",
            name="cloudtrail_log_file_validation",
            data_source="cloudtrail_trails",
            collection_mode="multiple",
            check_arguments=[
                "trail_arn",
                "name",
                "enable_log_file_validation",
            ],
            check=check_cloudtrail_log_file_validation,
            build_finding=build_cloudtrail_log_file_validation_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CT-004",
            name="cloudtrail_multi_region",
            data_source="cloudtrail_trails",
            collection_mode="multiple",
            check_arguments=[
                "trail_arn",
                "name",
                "is_multi_region_trail",
            ],
            check=check_cloudtrail_multi_region,
            build_finding=build_cloudtrail_multi_region_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CT-005",
            name="cloudtrail_global_service_events",
            data_source="cloudtrail_trails",
            collection_mode="multiple",
            check_arguments=[
                "trail_arn",
                "name",
                "include_global_service_events",
            ],
            check=check_cloudtrail_global_service_events,
            build_finding=build_cloudtrail_global_service_events_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CT-006",
            name="cloudtrail_encryption",
            data_source="cloudtrail_trails",
            collection_mode="multiple",
            check_arguments=[
                "trail_arn",
                "name",
                "kms_key_id",
            ],
            check=check_cloudtrail_encryption,
            build_finding=build_cloudtrail_encryption_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CT-007",
            name="cloudtrail_management_events",
            data_source="cloudtrail_trails",
            collection_mode="multiple",
            check_arguments=[
                "trail_arn",
                "name",
                "includes_management_events",
            ],
            check=check_cloudtrail_management_events,
            build_finding=build_cloudtrail_management_events_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CT-008",
            name="cloudtrail_cloudwatch_logs",
            data_source="cloudtrail_trails",
            collection_mode="multiple",
            check_arguments=[
                "trail_arn",
                "name",
                "cloudwatch_logs_log_group_arn",
                "cloudwatch_logs_role_arn",
            ],
            check=check_cloudtrail_cloudwatch_logs,
            build_finding=build_cloudtrail_cloudwatch_logs_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CT-009",
            name="cloudtrail_tagging",
            data_source="cloudtrail_trails",
            collection_mode="multiple",
            check_arguments=[
                "trail_arn",
                "name",
                "tags",
            ],
            check=check_cloudtrail_tagging,
            build_finding=build_cloudtrail_tagging_finding,
        ),
    ]
)