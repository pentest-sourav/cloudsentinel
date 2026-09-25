from engine.findings.model import Finding, Severity
from engine.rules.aws.cloudwatch.protection import (
    check_cloudwatch_alarm_actions,
    check_cloudwatch_alarm_actions_enabled,
    check_cloudwatch_log_retention,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


def _build_alarm_actions_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDWATCH-001",
        title=(
            "CloudWatch Alarm Has No ALARM Action"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="cloudwatch_alarm",
        resource_id=result.resource_id,
        description=(
            f"The CloudWatch alarm "
            f"{result.resource_id} does not have "
            "an action configured for the ALARM state."
        ),
        evidence={
            "alarm_arn": result.alarm_arn,
            "alarm_actions": result.alarm_actions,
            "state_value": result.state_value,
        },
        remediation=(
            "Configure at least one action for the "
            "CloudWatch alarm ALARM state, such as "
            "publishing a notification to an SNS topic "
            "or invoking another supported alarm action."
        ),
        compliance=[
            "AWS Security Hub CloudWatch.15",
        ],
    )


def _build_alarm_enabled_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDWATCH-002",
        title=(
            "CloudWatch Alarm Actions Are Disabled"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="cloudwatch_alarm",
        resource_id=result.resource_id,
        description=(
            f"The CloudWatch alarm "
            f"{result.resource_id} does not have "
            "alarm actions enabled."
        ),
        evidence={
            "alarm_arn": result.alarm_arn,
            "actions_enabled": result.actions_enabled,
            "state_value": result.state_value,
        },
        remediation=(
            "Enable actions for the CloudWatch alarm "
            "so configured alarm actions can execute "
            "when the alarm state changes."
        ),
        compliance=[
            "AWS Security Hub CloudWatch.17",
        ],
    )


def _build_log_retention_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CLOUDWATCH-003",
        title=(
            "CloudWatch Log Group Retention Is Below "
            "the Required Minimum"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudwatch_log_group",
        resource_id=result.resource_id,
        description=(
            f"The CloudWatch log group "
            f"{result.resource_id} has a retention "
            f"period of {result.retention_in_days!r} "
            f"days, which is below the configured "
            f"minimum of "
            f"{result.minimum_retention_days} days."
        ),
        evidence={
            "log_group_name": result.resource_id,
            "retention_in_days": (
                result.retention_in_days
            ),
            "minimum_retention_days": (
                result.minimum_retention_days
            ),
        },
        remediation=(
            "Configure the CloudWatch log group with "
            "a retention period that meets the "
            "organization's required minimum. The "
            "default CloudSentinel threshold is "
            "365 days."
        ),
        compliance=[
            "AWS Security Hub CloudWatch.16",
        ],
    )


CLOUDWATCH_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-001",
            name=(
                "CloudWatch alarms should have "
                "specified actions configured"
            ),
            data_source="cloudwatch_alarms",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "alarm_arn",
                "alarm_actions",
                "state_value",
            ],
            check=check_cloudwatch_alarm_actions,
            build_finding=_build_alarm_actions_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-002",
            name=(
                "CloudWatch alarm actions should "
                "be enabled"
            ),
            data_source="cloudwatch_alarms",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "alarm_arn",
                "actions_enabled",
                "state_value",
            ],
            check=check_cloudwatch_alarm_actions_enabled,
            build_finding=_build_alarm_enabled_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-003",
            name=(
                "CloudWatch log groups should be "
                "retained for the required period"
            ),
            data_source="cloudwatch_log_groups",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "retention_in_days",
            ],
            check=check_cloudwatch_log_retention,
            build_finding=_build_log_retention_finding,
        ),
    ]
)
