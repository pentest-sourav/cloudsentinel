from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.global_service_events import (
    build_cloudtrail_global_service_events_finding,
    check_cloudtrail_global_service_events,
)


TRAIL_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:trail/cloudtrail-main"
)


def test_global_service_events_disabled_is_detected():
    result = check_cloudtrail_global_service_events(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        include_global_service_events=False,
    )

    assert result is not None
    assert result.trail_arn == TRAIL_ARN
    assert result.name == "cloudtrail-main"
    assert result.include_global_service_events is False


def test_global_service_events_enabled_is_ignored():
    result = check_cloudtrail_global_service_events(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        include_global_service_events=True,
    )

    assert result is None


def test_missing_global_service_events_configuration_is_detected():
    result = check_cloudtrail_global_service_events(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        include_global_service_events=None,
    )

    assert result is not None
    assert result.include_global_service_events is False


def test_global_service_events_finding_is_built_correctly():
    result = check_cloudtrail_global_service_events(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        include_global_service_events=False,
    )

    finding = build_cloudtrail_global_service_events_finding(result)

    assert finding.rule_id == "CS-AWS-CT-005"
    assert finding.title == (
        "CloudTrail trail does not include global service events"
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == TRAIL_ARN

    assert finding.evidence == {
        "trail_arn": TRAIL_ARN,
        "trail_name": "cloudtrail-main",
        "include_global_service_events": False,
    }

    assert finding.remediation
    assert "CIS AWS Foundations" in finding.compliance
