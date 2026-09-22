from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailCloudWatchLogsResult:
    trail_arn: str
    name: str | None
    cloudwatch_logs_log_group_arn: str | None
    cloudwatch_logs_role_arn: str | None


def check_cloudtrail_cloudwatch_logs(
    trail_arn: str,
    name: str | None,
    cloudwatch_logs_log_group_arn: str | None,
    cloudwatch_logs_role_arn: str | None,
) -> CloudTrailCloudWatchLogsResult | None:
    """
    Detect a CloudTrail trail that is not configured
    to send events to Amazon CloudWatch Logs.
    """
    if cloudwatch_logs_log_group_arn:
        return None

    return CloudTrailCloudWatchLogsResult(
        trail_arn=trail_arn,
        name=name,
        cloudwatch_logs_log_group_arn=None,
        cloudwatch_logs_role_arn=cloudwatch_logs_role_arn,
    )


def build_cloudtrail_cloudwatch_logs_finding(
    result: CloudTrailCloudWatchLogsResult,
) -> Finding:
    """
    Build a finding for a CloudTrail trail that is not
    integrated with Amazon CloudWatch Logs.
    """
    return Finding(
        rule_id="CS-AWS-CT-008",
        title="CloudTrail trail is not integrated with CloudWatch Logs",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=(
            "The CloudTrail trail is not configured to send its "
            "events to an Amazon CloudWatch Logs log group. "
            "CloudWatch Logs integration supports centralized "
            "monitoring, alerting, and near real-time analysis "
            "of CloudTrail activity."
        ),
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "cloudwatch_logs_log_group_arn": (
                result.cloudwatch_logs_log_group_arn
            ),
            "cloudwatch_logs_role_arn": (
                result.cloudwatch_logs_role_arn
            ),
        },
        remediation=(
            "Configure the CloudTrail trail to deliver events "
            "to an appropriate Amazon CloudWatch Logs log group "
            "and provide a role that grants CloudTrail the "
            "required CloudWatch Logs permissions."
        ),
        compliance=["CIS AWS Foundations"],
    )
