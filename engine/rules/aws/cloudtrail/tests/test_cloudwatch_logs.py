from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.cloudwatch_logs import (
    CloudTrailCloudWatchLogsResult,
    build_cloudtrail_cloudwatch_logs_finding,
    check_cloudtrail_cloudwatch_logs,
)


TRAIL_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:trail/cloudtrail-main"
)


def test_cloudwatch_logs_integration_missing_is_detected():
    result = check_cloudtrail_cloudwatch_logs(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        cloudwatch_logs_log_group_arn=None,
        cloudwatch_logs_role_arn=None,
    )

    assert isinstance(
        result,
        CloudTrailCloudWatchLogsResult,
    )

    assert result.trail_arn == TRAIL_ARN
    assert result.name == "cloudtrail-main"
    assert result.cloudwatch_logs_log_group_arn is None
    assert result.cloudwatch_logs_role_arn is None


def test_cloudwatch_logs_integration_present_is_ignored():
    result = check_cloudtrail_cloudwatch_logs(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        cloudwatch_logs_log_group_arn=(
            "arn:aws:logs:eu-north-1:"
            "123456789012:log-group:/aws/cloudtrail/main"
        ),
        cloudwatch_logs_role_arn=(
            "arn:aws:iam::123456789012:"
            "role/CloudTrail_CloudWatchLogs_Role"
        ),
    )

    assert result is None


def test_cloudwatch_logs_finding_is_built_correctly():
    result = CloudTrailCloudWatchLogsResult(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        cloudwatch_logs_log_group_arn=None,
        cloudwatch_logs_role_arn=(
            "arn:aws:iam::123456789012:"
            "role/CloudTrail_CloudWatchLogs_Role"
        ),
    )

    finding = build_cloudtrail_cloudwatch_logs_finding(result)

    assert finding.rule_id == "CS-AWS-CT-008"
    assert (
        finding.title
        == "CloudTrail trail is not integrated with CloudWatch Logs"
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == TRAIL_ARN

    assert finding.evidence["trail_arn"] == TRAIL_ARN
    assert finding.evidence["trail_name"] == "cloudtrail-main"
    assert (
        finding.evidence["cloudwatch_logs_log_group_arn"]
        is None
    )
    assert (
        finding.evidence["cloudwatch_logs_role_arn"]
        == (
            "arn:aws:iam::123456789012:"
            "role/CloudTrail_CloudWatchLogs_Role"
        )
    )

    assert finding.compliance == ["CIS AWS Foundations"]
