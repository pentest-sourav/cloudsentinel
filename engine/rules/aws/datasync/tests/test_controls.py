from engine.findings.model import Severity

from engine.rules.aws.datasync.controls import (
    check_datasync_task_logging,
    check_datasync_task_tags,
    build_datasync_task_logging_finding,
    build_datasync_task_tags_finding,
)


def test_datasync_logging_passes_for_basic_task():
    result = check_datasync_task_logging(
        "task",
        "arn:task",
        "AWS::DataSync::Task",
        "BASIC",
        "BASIC",
        "arn:logs",
    )

    assert result is None


def test_datasync_logging_fails_when_disabled():
    result = check_datasync_task_logging(
        "task",
        "arn:task",
        "AWS::DataSync::Task",
        "BASIC",
        "OFF",
        "arn:logs",
    )

    assert result is not None
    assert result.control_id == "DataSync.1"
    assert result.reason == "task_logging_disabled"

    finding = build_datasync_task_logging_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-DATASYNC-001"
    assert finding.severity == Severity.MEDIUM


def test_datasync_logging_fails_without_log_group():
    result = check_datasync_task_logging(
        "task",
        "arn:task",
        "AWS::DataSync::Task",
        "BASIC",
        "BASIC",
        None,
    )

    assert result is not None
    assert (
        result.reason
        == "cloudwatch_log_group_not_configured"
    )


def test_enhanced_mode_does_not_require_explicit_log_group():
    result = check_datasync_task_logging(
        "task",
        "arn:task",
        "AWS::DataSync::Task",
        "ENHANCED",
        "BASIC",
        None,
    )

    assert result is None


def test_enhanced_mode_with_off_logging_fails():
    result = check_datasync_task_logging(
        "task",
        "arn:task",
        "AWS::DataSync::Task",
        "ENHANCED",
        "OFF",
        None,
    )

    assert result is not None


def test_datasync_tags_pass():
    result = check_datasync_task_tags(
        "task",
        "arn:task",
        "AWS::DataSync::Task",
        True,
        True,
    )

    assert result is None


def test_datasync_tags_fail():
    result = check_datasync_task_tags(
        "task",
        "arn:task",
        "AWS::DataSync::Task",
        True,
        False,
    )

    assert result is not None
    assert result.control_id == "DataSync.2"
    assert result.reason == "missing_non_system_tags"

    finding = build_datasync_task_tags_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-DATASYNC-002"
    assert finding.severity == Severity.LOW


def test_datasync_tags_skip_when_tag_data_unavailable():
    result = check_datasync_task_tags(
        "task",
        "arn:task",
        "AWS::DataSync::Task",
        False,
        False,
    )

    assert result is None
