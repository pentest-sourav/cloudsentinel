from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.no_trail import (
    build_cloudtrail_no_trail_finding,
    check_cloudtrail_no_trail,
)


def test_no_trail_returns_result_when_trail_count_is_zero():
    result = check_cloudtrail_no_trail(0)

    assert result is not None
    assert result.trail_count == 0


def test_no_trail_returns_none_when_trail_exists():
    result = check_cloudtrail_no_trail(1)

    assert result is None


def test_no_trail_finding_contains_expected_details():
    result = check_cloudtrail_no_trail(0)

    finding = build_cloudtrail_no_trail_finding(result)

    assert finding.rule_id == "CS-AWS-CT-002"
    assert finding.title == "No CloudTrail trail is configured"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == "aws-account"
    assert finding.evidence["trail_count"] == 0
