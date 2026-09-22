from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.log_file_validation import (
    build_cloudtrail_log_file_validation_finding,
    check_cloudtrail_log_file_validation,
)


TRAIL_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:trail/cloudtrail-main"
)


def test_disabled_log_file_validation_is_detected():
    result = check_cloudtrail_log_file_validation(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        enable_log_file_validation=False,
    )

    assert result is not None
    assert result.trail_arn == TRAIL_ARN
    assert result.name == "cloudtrail-main"
    assert result.log_file_validation_enabled is False


def test_enabled_log_file_validation_is_ignored():
    result = check_cloudtrail_log_file_validation(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        enable_log_file_validation=True,
    )

    assert result is None


def test_missing_log_file_validation_is_detected():
    result = check_cloudtrail_log_file_validation(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        enable_log_file_validation=None,
    )

    assert result is not None
    assert result.log_file_validation_enabled is False


def test_log_file_validation_finding_is_built_correctly():
    result = check_cloudtrail_log_file_validation(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        enable_log_file_validation=False,
    )

    finding = build_cloudtrail_log_file_validation_finding(result)

    assert finding.rule_id == "CS-AWS-CT-003"
    assert finding.title == (
        "CloudTrail log file validation is disabled"
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == TRAIL_ARN

    assert finding.evidence == {
        "trail_arn": TRAIL_ARN,
        "trail_name": "cloudtrail-main",
        "log_file_validation_enabled": False,
    }

    assert finding.remediation
    assert "CIS AWS Foundations" in finding.compliance
