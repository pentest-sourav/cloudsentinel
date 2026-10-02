from engine.rules.aws.cloudtrail.tagging import (
    build_cloudtrail_tagging_finding,
    check_cloudtrail_tagging,
)


def test_cloudtrail_tagging_requires_all_configured_keys():
    result = check_cloudtrail_tagging(
        trail_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/test",
        name="test",
        tags=[
            {"Key": "Environment", "Value": "prod"},
        ],
        required_tag_keys=["Environment", "Owner"],
    )

    assert result.required_tag_keys == [
        "Environment",
        "Owner",
    ]
    assert result.missing_tag_keys == ["Owner"]

    finding = build_cloudtrail_tagging_finding(result)

    assert finding is not None
    assert finding.evidence["required_tag_keys"] == [
        "Environment",
        "Owner",
    ]
    assert finding.evidence["missing_tag_keys"] == ["Owner"]


def test_cloudtrail_tagging_is_compliant_when_all_required_keys_exist():
    result = check_cloudtrail_tagging(
        trail_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/test",
        name="test",
        tags=[
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Owner", "Value": "security"},
        ],
        required_tag_keys=["Environment", "Owner"],
    )

    assert result.missing_tag_keys == []
    assert build_cloudtrail_tagging_finding(result) is None


def test_cloudtrail_tagging_matching_is_case_sensitive():
    result = check_cloudtrail_tagging(
        trail_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/test",
        name="test",
        tags=[
            {"Key": "environment", "Value": "prod"},
        ],
        required_tag_keys=["Environment"],
    )

    assert result.missing_tag_keys == ["Environment"]


def test_cloudtrail_tagging_ignores_system_required_keys():
    result = check_cloudtrail_tagging(
        trail_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/test",
        name="test",
        tags=[
            {"Key": "Environment", "Value": "prod"},
        ],
        required_tag_keys=[
            "Environment",
            "aws:createdBy",
            "",
            "Environment",
        ],
    )

    assert result.required_tag_keys == ["Environment"]
    assert result.missing_tag_keys == []
    assert build_cloudtrail_tagging_finding(result) is None


def test_cloudtrail_tagging_preserves_baseline_without_parameters():
    result = check_cloudtrail_tagging(
        trail_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/test",
        name="test",
        tags=[],
    )

    assert result.required_tag_keys == []
    assert result.missing_tag_keys == []

    finding = build_cloudtrail_tagging_finding(result)

    assert finding is not None
    assert finding.rule_id == "CS-AWS-CT-009"


def test_cloudtrail_tagging_baseline_accepts_any_non_system_tag():
    result = check_cloudtrail_tagging(
        trail_arn="arn:aws:cloudtrail:us-east-1:123456789012:trail/test",
        name="test",
        tags=[
            {"Key": "Environment", "Value": "prod"},
        ],
    )

    assert build_cloudtrail_tagging_finding(result) is None
