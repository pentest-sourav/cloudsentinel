from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.management_events import (
    CloudTrailManagementEventsResult,
    build_cloudtrail_management_events_finding,
    check_cloudtrail_management_events,
)


TRAIL_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:trail/cloudtrail-main"
)


def test_management_events_disabled_is_detected():
    result = check_cloudtrail_management_events(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        includes_management_events=False,
    )

    assert isinstance(
        result,
        CloudTrailManagementEventsResult,
    )

    assert result.trail_arn == TRAIL_ARN
    assert result.name == "cloudtrail-main"
    assert result.includes_management_events is False


def test_management_events_enabled_is_ignored():
    result = check_cloudtrail_management_events(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        includes_management_events=True,
    )

    assert result is None


def test_management_events_finding_is_built_correctly():
    result = CloudTrailManagementEventsResult(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        includes_management_events=False,
    )

    finding = build_cloudtrail_management_events_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-CT-007"
    assert (
        finding.title
        == "CloudTrail trail does not include management events"
    )
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == TRAIL_ARN
    assert finding.evidence["trail_arn"] == TRAIL_ARN
    assert finding.evidence["trail_name"] == "cloudtrail-main"
    assert (
        finding.evidence["includes_management_events"]
        is False
    )
    assert finding.compliance == ["CIS AWS Foundations"]
