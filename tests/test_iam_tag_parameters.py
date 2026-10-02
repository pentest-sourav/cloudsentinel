from engine.rules.aws.iam.tagging import check_iam_tagging


def _check(
    tags,
    required_tag_keys=None,
):
    return check_iam_tagging(
        rule_id="CS-AWS-IAM-040",
        resource_type="iam_test",
        resource_id="arn:test",
        title="IAM Test",
        tags=tags,
        required_tag_keys=required_tag_keys,
    )


def test_no_parameter_preserves_baseline_behavior():
    assert _check({"Environment": "prod"}) is None
    assert _check({}) is not None


def test_empty_parameter_preserves_baseline_behavior():
    assert _check(
        {"Environment": "prod"},
        [],
    ) is None

    assert _check(
        {},
        [],
    ) is not None


def test_required_tag_key_present():
    assert _check(
        {"Environment": "prod"},
        ["Environment"],
    ) is None


def test_required_tag_key_missing():
    result = _check(
        {"Environment": "prod"},
        ["Owner"],
    )

    assert result is not None
    assert result.missing_tag_keys == ["Owner"]


def test_all_required_tag_keys_are_required():
    result = _check(
        {
            "Environment": "prod",
            "Owner": "Sourav",
        },
        [
            "Environment",
            "Owner",
            "Application",
        ],
    )

    assert result is not None
    assert result.missing_tag_keys == ["Application"]


def test_system_tags_are_ignored():
    result = _check(
        {
            "aws:createdBy": "system",
        },
        ["aws:createdBy"],
    )

    assert result is not None
    assert result.required_tag_keys == []
    assert result.missing_tag_keys == []


def test_required_tag_keys_are_case_sensitive():
    result = _check(
        {"environment": "prod"},
        ["Environment"],
    )

    assert result is not None
    assert result.missing_tag_keys == ["Environment"]


def test_required_tag_keys_are_deduplicated():
    result = _check(
        {},
        [
            "Owner",
            "Owner",
        ],
    )

    assert result is not None
    assert result.required_tag_keys == ["Owner"]
    assert result.missing_tag_keys == ["Owner"]
