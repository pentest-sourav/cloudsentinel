from engine.findings.model import Severity
from engine.rules.aws.cloudwatch.protection import (
    check_cloudwatch_alarm_actions,
    check_cloudwatch_alarm_actions_enabled,
    check_cloudwatch_log_retention,
)
from engine.rules.registry.cloudwatch_registry import (
    _build_alarm_actions_finding,
    _build_alarm_enabled_finding,
    _build_log_retention_finding,
)


def test_alarm_without_actions_is_detected():
    result = check_cloudwatch_alarm_actions(
        resource_id="alarm-1",
        alarm_arn="arn:alarm:1",
        alarm_actions=[],
        state_value="OK",
    )

    assert result is not None
    assert result.resource_id == "alarm-1"


def test_alarm_with_actions_is_not_detected():
    result = check_cloudwatch_alarm_actions(
        resource_id="alarm-1",
        alarm_arn="arn:alarm:1",
        alarm_actions=["arn:sns:test"],
        state_value="OK",
    )

    assert result is None


def test_missing_alarm_id_is_ignored():
    result = check_cloudwatch_alarm_actions(
        resource_id="",
        alarm_arn=None,
        alarm_actions=[],
        state_value=None,
    )

    assert result is None


def test_alarm_without_actions_finding():
    result = check_cloudwatch_alarm_actions(
        resource_id="alarm-1",
        alarm_arn="arn:alarm:1",
        alarm_actions=[],
        state_value="OK",
    )

    finding = _build_alarm_actions_finding(result)

    assert finding.rule_id == "CS-AWS-CLOUDWATCH-001"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "cloudwatch_alarm"
    assert finding.resource_id == "alarm-1"
    assert finding.evidence["alarm_actions"] == []


def test_disabled_alarm_actions_are_detected():
    result = check_cloudwatch_alarm_actions_enabled(
        resource_id="alarm-1",
        alarm_arn="arn:alarm:1",
        actions_enabled=False,
        state_value="ALARM",
    )

    assert result is not None
    assert result.actions_enabled is False


def test_enabled_alarm_actions_are_not_detected():
    result = check_cloudwatch_alarm_actions_enabled(
        resource_id="alarm-1",
        alarm_arn="arn:alarm:1",
        actions_enabled=True,
        state_value="OK",
    )

    assert result is None


def test_missing_actions_enabled_value_is_detected():
    result = check_cloudwatch_alarm_actions_enabled(
        resource_id="alarm-1",
        alarm_arn="arn:alarm:1",
        actions_enabled=None,
        state_value=None,
    )

    assert result is not None


def test_disabled_alarm_actions_finding():
    result = check_cloudwatch_alarm_actions_enabled(
        resource_id="alarm-1",
        alarm_arn="arn:alarm:1",
        actions_enabled=False,
        state_value="ALARM",
    )

    finding = _build_alarm_enabled_finding(result)

    assert finding.rule_id == "CS-AWS-CLOUDWATCH-002"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "cloudwatch_alarm"
    assert finding.resource_id == "alarm-1"
    assert finding.evidence["actions_enabled"] is False


def test_log_group_below_minimum_retention_is_detected():
    result = check_cloudwatch_log_retention(
        resource_id="/aws/test",
        retention_in_days=30,
    )

    assert result is not None
    assert result.retention_in_days == 30
    assert result.minimum_retention_days == 365


def test_log_group_without_retention_is_detected():
    result = check_cloudwatch_log_retention(
        resource_id="/aws/test",
        retention_in_days=None,
    )

    assert result is not None
    assert result.retention_in_days is None


def test_log_group_meeting_minimum_retention_is_not_detected():
    result = check_cloudwatch_log_retention(
        resource_id="/aws/test",
        retention_in_days=365,
    )

    assert result is None


def test_log_group_custom_retention_threshold():
    result = check_cloudwatch_log_retention(
        resource_id="/aws/test",
        retention_in_days=90,
        minimum_retention_days=90,
    )

    assert result is None


def test_log_group_retention_finding():
    result = check_cloudwatch_log_retention(
        resource_id="/aws/test",
        retention_in_days=30,
    )

    finding = _build_log_retention_finding(result)

    assert finding.rule_id == "CS-AWS-CLOUDWATCH-003"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "cloudwatch_log_group"
    assert finding.resource_id == "/aws/test"
    assert finding.evidence["retention_in_days"] == 30


def test_boolean_retention_value_is_not_treated_as_integer():
    result = check_cloudwatch_log_retention(
        resource_id="/aws/test",
        retention_in_days=True,
    )

    assert result is not None
    assert result.retention_in_days is None
