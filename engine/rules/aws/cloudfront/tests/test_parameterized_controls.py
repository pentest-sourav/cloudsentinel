from engine.rules.aws.cloudfront.tagging import (
    build_cloudfront_tagging_finding,
    check_cloudfront_tagging,
)


def test_cloudfront_tagging_passes_with_required_keys():
    result = check_cloudfront_tagging(
        "D123",
        [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Owner", "Value": "platform"},
        ],
        ["Environment", "Owner"],
    )

    assert result is None


def test_cloudfront_tagging_fails_when_required_key_missing():
    result = check_cloudfront_tagging(
        "D123",
        [
            {"Key": "Environment", "Value": "prod"},
        ],
        ["Environment", "Owner"],
    )

    assert result is not None
    assert result.missing_tag_keys == ["Owner"]

    finding = build_cloudfront_tagging_finding(result)

    assert finding.rule_id == "CS-AWS-CLOUDFRONT-014"


def test_cloudfront_tagging_is_case_sensitive():
    result = check_cloudfront_tagging(
        "D123",
        [
            {"Key": "environment", "Value": "prod"},
        ],
        ["Environment"],
    )

    assert result is not None
    assert result.missing_tag_keys == ["Environment"]


def test_cloudfront_tagging_ignores_system_tags():
    result = check_cloudfront_tagging(
        "D123",
        [
            {"Key": "aws:test", "Value": "x"},
        ],
        [],
    )

    assert result is not None


def test_cloudfront_tagging_baseline_behavior():
    result = check_cloudfront_tagging(
        "D123",
        [
            {"Key": "Environment", "Value": "prod"},
        ],
        [],
    )

    assert result is None
