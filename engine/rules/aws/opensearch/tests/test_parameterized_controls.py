from engine.rules.aws.opensearch.tagging import (
    check_opensearch_tagging,
)


def test_opensearch_tagging_passes_with_required_keys():
    result = check_opensearch_tagging(
        "arn:aws:es:region:123:domain/test",
        [
            {"Key": "Environment", "Value": "prod"},
            {"Key": "Owner", "Value": "platform"},
        ],
        ["Environment", "Owner"],
    )

    assert result.tagged is True
    assert result.missing_tag_keys == []


def test_opensearch_tagging_fails_when_required_key_missing():
    result = check_opensearch_tagging(
        "arn:aws:es:region:123:domain/test",
        [
            {"Key": "Environment", "Value": "prod"},
        ],
        ["Environment", "Owner"],
    )

    assert result.tagged is False
    assert result.missing_tag_keys == ["Owner"]


def test_opensearch_tagging_is_case_sensitive():
    result = check_opensearch_tagging(
        "arn:aws:es:region:123:domain/test",
        [
            {"Key": "environment", "Value": "prod"},
        ],
        ["Environment"],
    )

    assert result.tagged is False
    assert result.missing_tag_keys == ["Environment"]


def test_opensearch_tagging_ignores_system_tags():
    result = check_opensearch_tagging(
        "arn:aws:es:region:123:domain/test",
        [
            {"Key": "aws:test", "Value": "x"},
        ],
        [],
    )

    assert result.tagged is False


def test_opensearch_tagging_baseline_behavior():
    result = check_opensearch_tagging(
        "arn:aws:es:region:123:domain/test",
        [
            {"Key": "Environment", "Value": "prod"},
        ],
        [],
    )

    assert result.tagged is True
