from engine.rules.aws.securityhub.protection import (
    build_hub_finding,
    build_standard_finding,
    check_hub_enabled,
    check_standard_ready,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


SECURITYHUB_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-SH-001",
            name=(
                "AWS Security Hub should be enabled"
            ),
            data_source="securityhub_hub",
            collection_mode="single",
            check_arguments=[
                "resource_id",
                "enabled",
            ],
            check=check_hub_enabled,
            build_finding=build_hub_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-SH-002",
            name=(
                "Enabled Security Hub standards "
                "should be ready"
            ),
            data_source="securityhub_standards",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "standards_subscription_arn",
                "standards_arn",
                "standards_status",
                "standards_controls_updatable",
                "standards_status_reason",
                "provider",
            ],
            check=check_standard_ready,
            build_finding=build_standard_finding,
        ),
    ]
)
