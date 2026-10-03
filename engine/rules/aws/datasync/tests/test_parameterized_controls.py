from engine.rules.aws.datasync.controls import (
    check_datasync_task_tags,
)


def test_datasync_tags_pass_with_required_keys():
    result = check_datasync_task_tags(
        "task",
        "arn:aws:datasync:region:123:task/task-1",
        "AWS::DataSync::Task",
        True,
        True,
        {
            "Environment": "prod",
            "Owner": "platform",
        },
        ["Environment", "Owner"],
    )

    assert result is None


def test_datasync_tags_fail_when_required_key_missing():
    result = check_datasync_task_tags(
        "task",
        "arn:aws:datasync:region:123:task/task-1",
        "AWS::DataSync::Task",
        True,
        True,
        {
            "Environment": "prod",
        },
        ["Environment", "Owner"],
    )

    assert result is not None
    assert result.reason == "missing_required_tag_keys"
    assert result.evidence["missing_tag_keys"] == ["Owner"]


def test_datasync_tags_are_case_sensitive():
    result = check_datasync_task_tags(
        "task",
        "arn:aws:datasync:region:123:task/task-1",
        "AWS::DataSync::Task",
        True,
        True,
        {
            "environment": "prod",
        },
        ["Environment"],
    )

    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["Environment"]


def test_datasync_tags_ignore_system_keys():
    result = check_datasync_task_tags(
        "task",
        "arn:aws:datasync:region:123:task/task-1",
        "AWS::DataSync::Task",
        True,
        True,
        {
            "aws:test": "x",
        },
        ["Environment"],
    )

    assert result is not None
    assert result.evidence["missing_tag_keys"] == ["Environment"]
