from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.logging import (
    build_cloudtrail_logging_finding,
    check_cloudtrail_logging,
)


TRAIL_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:trail/cloudtrail-main"
)


def test_non_logging_cloudtrail_trail_is_detected():
    result = check_cloudtrail_logging(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        is_logging=False,
    )

    assert result is not None
    assert result.trail_arn == TRAIL_ARN
    assert result.name == "cloudtrail-main"
    assert result.is_logging is False


def test_logging_cloudtrail_trail_is_ignored():
    result = check_cloudtrail_logging(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        is_logging=True,
    )

    assert result is None


def test_cloudtrail_logging_finding_is_built_correctly():
    result = check_cloudtrail_logging(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        is_logging=False,
    )

    finding = build_cloudtrail_logging_finding(result)

    assert finding.rule_id == "CS-AWS-CT-001"
    assert finding.title == (
        "CloudTrail trail is not actively logging"
    )
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == TRAIL_ARN

    assert finding.evidence == {
        "trail_arn": TRAIL_ARN,
        "trail_name": "cloudtrail-main",
        "is_logging": False,
    }

    assert finding.remediation
    assert "CIS AWS Foundations" in finding.compliance
