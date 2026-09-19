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
    ]
)
