from engine.rules.aws.glue.protection import check_glue_job_tags


def _check(
    tags,
    required_tag_keys=None,
):
    non_system_tags = {
        key: value
        for key, value in tags.items()
        if isinstance(key, str) and not key.lower().startswith("aws:")
    }

    return check_glue_job_tags(
        job_name="test-job",
        has_non_system_tags=bool(non_system_tags),
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


def test_system_tag_is_ignored():
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
