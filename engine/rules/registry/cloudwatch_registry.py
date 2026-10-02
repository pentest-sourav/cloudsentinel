from engine.findings.model import Finding, Severity
from engine.rules.aws.cloudwatch.protection import (
    check_cloudwatch_alarm_actions,
    check_cloudwatch_alarm_actions_enabled,
    check_cloudwatch_log_retention,
    check_cloudwatch_log_metric_alarm,
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


def _build_log_metric_alarm_finding(
    result,
) -> Finding:
    return Finding(
        rule_id=(
            f"CS-AWS-CLOUDWATCH-"
            f"{int(result.control_id) + 3:03d}"
        ),
        title=(
            "CloudWatch security metric filter and "
            "alarm are not configured"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type="cloudwatch_security_control",
        resource_id=result.resource_id,
        description=(
            f"CloudWatch.{result.control_id} does not have "
            "the required AWS-prescribed CloudTrail log "
            "metric filter, CloudWatch alarm, and SNS "
            "notification chain."
        ),
        evidence=result.evidence,
        remediation=(
            "Configure the exact AWS-prescribed CloudWatch "
            "Logs metric filter on a CloudTrail log group, "
            "create a CloudWatch alarm using the resulting "
            "LogMetrics metric with a threshold of at least 1, "
            "and configure an SNS notification action with "
            "at least one subscription."
        ),
        compliance=[
            f"AWS Security Hub CloudWatch.{result.control_id}",
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
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-004",
            name=(
                "CloudWatch.1 should detect "
                "root user usage"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_1"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-005",
            name=(
                "CloudWatch.2 should detect "
                "unauthorized API calls"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_2"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-006",
            name=(
                "CloudWatch.3 should detect "
                "console sign-in without MFA"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_3"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-007",
            name=(
                "CloudWatch.4 should detect "
                "IAM policy changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_4"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-008",
            name=(
                "CloudWatch.5 should detect "
                "CloudTrail configuration changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_5"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-009",
            name=(
                "CloudWatch.6 should detect "
                "console authentication failures"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_6"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-010",
            name=(
                "CloudWatch.7 should detect "
                "KMS DisableKey or ScheduleKeyDeletion"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_7"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-011",
            name=(
                "CloudWatch.8 should detect "
                "S3 bucket policy changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_8"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-012",
            name=(
                "CloudWatch.9 should detect "
                "AWS Config changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_9"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-013",
            name=(
                "CloudWatch.10 should detect "
                "security group changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_10"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-014",
            name=(
                "CloudWatch.11 should detect "
                "network ACL changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_11"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-015",
            name=(
                "CloudWatch.12 should detect "
                "network gateway changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_12"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-016",
            name=(
                "CloudWatch.13 should detect "
                "route table changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_13"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
        RuleDefinition(
            rule_id="CS-AWS-CLOUDWATCH-017",
            name=(
                "CloudWatch.14 should detect "
                "VPC changes"
            ),
            data_source=(
                "cloudwatch_log_metric_alarm_control_14"
            ),
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "control_id",
                "compliant",
                "evidence",
            ],
            check=check_cloudwatch_log_metric_alarm,
            build_finding=_build_log_metric_alarm_finding,
        ),
    ]
)
