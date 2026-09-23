from engine.findings.model import Severity

from engine.rules.aws.cloudtrail.tagging import (
    CloudTrailTaggingResult,
    build_cloudtrail_tagging_finding,
    check_cloudtrail_tagging,
)


TRAIL_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:trail/cloudtrail-main"
)


def test_cloudtrail_without_tags_is_detected():
    result = check_cloudtrail_tagging(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        tags=[],
    )

    assert isinstance(result, CloudTrailTaggingResult)
    assert result.trail_arn == TRAIL_ARN
    assert result.name == "cloudtrail-main"
    assert result.tags == []
    assert result.tagged is False


def test_cloudtrail_with_tags_is_ignored():
    result = check_cloudtrail_tagging(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        tags=[
            {
                "Key": "Environment",
                "Value": "Production",
            }
        ],
    )

    assert result.tagged is True
    assert build_cloudtrail_tagging_finding(result) is None


def test_cloudtrail_tagging_finding_is_built_correctly():
    result = check_cloudtrail_tagging(
        trail_arn=TRAIL_ARN,
        name="cloudtrail-main",
        tags=[],
    )

    finding = build_cloudtrail_tagging_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-009"
    assert finding.title == "CloudTrail trail is not tagged"
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "cloudtrail"
    assert finding.resource_id == TRAIL_ARN
    assert finding.evidence["trail_arn"] == TRAIL_ARN
    assert finding.evidence["trail_name"] == "cloudtrail-main"
    assert finding.evidence["tags"] == []
    assert finding.evidence["tag_count"] == 0
    assert finding.compliance == ["AWS Resource Tagging Standard"]
