from datetime import datetime, timezone

from engine.findings.model import Severity
from engine.rules.aws.iam.access_key_age import (
    build_access_key_age_finding,
    check_access_key_age,
)


def test_active_access_key_older_than_90_days_is_flagged():
    created_at = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    current_time = datetime(
        2026,
        4,
        15,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="test-user",
        access_key_id="AKIAOLD123",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is not None
    assert result.username == "test-user"
    assert result.access_key_id == "AKIAOLD123"
    assert result.age_days == 104
    assert result.threshold_days == 90


def test_active_access_key_within_90_days_is_not_flagged():
    created_at = datetime(
        2026,
        3,
        1,
        tzinfo=timezone.utc,
    )

    current_time = datetime(
        2026,
        4,
        15,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="test-user",
        access_key_id="AKIARECENT123",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is None


def test_inactive_old_access_key_is_not_flagged():
    created_at = datetime(
        2025,
        1,
        1,
        tzinfo=timezone.utc,
    )

    current_time = datetime(
        2026,
        4,
        15,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="test-user",
        access_key_id="AKIAINACTIVE123",
        status="Inactive",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is None


def test_access_key_age_finding_contains_expected_details():
    created_at = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    current_time = datetime(
        2026,
        4,
        15,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="test-user",
        access_key_id="AKIAOLD123",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    finding = build_access_key_age_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-003"
    assert finding.severity == Severity.HIGH
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_access_key"
    assert finding.resource_id == "AKIAOLD123"

    assert finding.evidence["username"] == "test-user"
    assert finding.evidence["access_key_id"] == "AKIAOLD123"
    assert finding.evidence["status"] == "Active"
    assert finding.evidence["age_days"] == 104
    assert finding.evidence["threshold_days"] == 90
