from datetime import datetime, timezone, timedelta

from engine.findings.model import Finding, Severity
from engine.rules.aws.ec2.stopped_instance import (
    StoppedInstanceResult,
    build_stopped_instance_finding,
    check_stopped_instance,
)


def _reason_for_days_ago(days: int) -> str:
    timestamp = (
        datetime.now(timezone.utc) - timedelta(days=days)
    ).strftime("%Y-%m-%d %H:%M:%S GMT")

    return f"User initiated ({timestamp})"


def test_stopped_instance_over_threshold_is_detected():
    result = check_stopped_instance(
        instance_id="i-001",
        instance_state="stopped",
        launch_time="2026-09-20T00:00:00+00:00",
        state_transition_reason=_reason_for_days_ago(31),
    )

    assert result is not None
    assert isinstance(result, StoppedInstanceResult)
    assert result.instance_id == "i-001"


def test_recently_stopped_instance_is_not_detected():
    result = check_stopped_instance(
        instance_id="i-002",
        instance_state="stopped",
        launch_time="2026-01-01T00:00:00+00:00",
        state_transition_reason=_reason_for_days_ago(10),
    )

    assert result is None


def test_running_instance_is_not_detected():
    result = check_stopped_instance(
        instance_id="i-003",
        instance_state="running",
        launch_time="2025-01-01T00:00:00+00:00",
        state_transition_reason=_reason_for_days_ago(100),
    )

    assert result is None


def test_exact_threshold_is_not_detected():
    result = check_stopped_instance(
        instance_id="i-004",
        instance_state="stopped",
        launch_time="2025-01-01T00:00:00+00:00",
        state_transition_reason=_reason_for_days_ago(30),
    )

    assert result is None


def test_missing_transition_reason_is_not_detected():
    result = check_stopped_instance(
        instance_id="i-005",
        instance_state="stopped",
        launch_time="2025-01-01T00:00:00+00:00",
        state_transition_reason=None,
    )

    assert result is None


def test_invalid_transition_reason_is_not_detected():
    result = check_stopped_instance(
        instance_id="i-006",
        instance_state="stopped",
        launch_time="2020-01-01T00:00:00+00:00",
        state_transition_reason="User initiated (invalid)",
    )

    assert result is None


def test_old_launch_time_does_not_trigger_without_stop_timestamp():
    result = check_stopped_instance(
        instance_id="i-007",
        instance_state="stopped",
        launch_time="2020-01-01T00:00:00+00:00",
        state_transition_reason=None,
    )

    assert result is None


def test_stopped_instance_finding_contains_expected_details():
    result = check_stopped_instance(
        instance_id="i-001",
        instance_state="stopped",
        launch_time="2026-01-01T00:00:00+00:00",
        state_transition_reason=_reason_for_days_ago(45),
    )

    assert result is not None

    finding = build_stopped_instance_finding(result)

    assert isinstance(finding, Finding)
    assert finding.rule_id == "CS-AWS-EC2-010"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_instance"
    assert finding.resource_id == "i-001"

    assert finding.evidence["instance_id"] == "i-001"
    assert finding.evidence["stopped_days"] >= 30

    assert finding.remediation
