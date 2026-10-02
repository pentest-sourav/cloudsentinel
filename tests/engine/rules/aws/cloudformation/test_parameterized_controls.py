from engine.rules.aws.cloudformation.controls import (
    check_cloudformation_stack_tags,
)


def test_cloudformation_required_tags_all_present():
    result = check_cloudformation_stack_tags(
        "stack-1",
        "arn:aws:cloudformation:region:123:stack/stack-1/id",
        True,
        True,
        {"Environment": "prod", "Owner": "security"},
        ["Environment", "Owner"],
    )
    assert result is None


def test_cloudformation_required_tags_missing():
    result = check_cloudformation_stack_tags(
        "stack-1",
        "arn:aws:cloudformation:region:123:stack/stack-1/id",
        True,
        True,
        {"Environment": "prod"},
        ["Environment", "Owner"],
    )
    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["Owner"]


def test_cloudformation_required_tags_case_sensitive():
    result = check_cloudformation_stack_tags(
        "stack-1",
        "arn:aws:cloudformation:region:123:stack/stack-1/id",
        True,
        True,
        {"environment": "prod"},
        ["Environment"],
    )
    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["Environment"]
