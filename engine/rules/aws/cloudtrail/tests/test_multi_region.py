from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.multi_region import (
    build_cloudtrail_multi_region_finding,
    check_cloudtrail_multi_region,
)


TRAIL_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:trail/cloudtrail-main"
)


def test_non_multi_region_trail_is_detected():
    result = check_cloudtrail_multi_region(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        is_multi_region_trail=False,
    )

    assert result is not None
    assert result.trail_arn == TRAIL_ARN
    assert result.name == "cloudtrail-main"
    assert result.is_multi_region_trail is False


def test_multi_region_trail_is_ignored():
    result = check_cloudtrail_multi_region(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        is_multi_region_trail=True,
    )

    assert result is None


def test_missing_multi_region_configuration_is_detected():
    result = check_cloudtrail_multi_region(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        is_multi_region_trail=None,
    )

    assert result is not None
    assert result.is_multi_region_trail is False


def test_multi_region_finding_is_built_correctly():
    result = check_cloudtrail_multi_region(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        is_multi_region_trail=False,
    )

    finding = build_cloudtrail_multi_region_finding(result)

    assert finding.rule_id == "CS-AWS-CT-004"
    assert finding.title == (
        "CloudTrail trail is not configured as multi-region"
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == TRAIL_ARN

    assert finding.evidence == {
        "trail_arn": TRAIL_ARN,
        "trail_name": "cloudtrail-main",
        "is_multi_region_trail": False,
    }

    assert finding.remediation
    assert "CIS AWS Foundations" in finding.compliance
