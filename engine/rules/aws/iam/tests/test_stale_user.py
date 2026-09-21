from datetime import datetime, timedelta, timezone

from engine.findings.model import Severity
from engine.rules.aws.iam.stale_user import (
    build_stale_iam_user_finding,
    check_stale_iam_user,
)


def test_stale_user_with_old_console_activity_is_flagged():
    current_time = datetime(
        2026, 9, 21, 12, 0, tzinfo=timezone.utc
    )
    last_activity_at = current_time - timedelta(days=91)

    result = check_stale_iam_user(
        username="alice",
        last_activity_at=last_activity_at,
        last_activity_type="console_password",
        last_activity_access_key_id=None,
        current_time=current_time,
    )

    assert result is not None
    assert result.username == "alice"
    assert result.age_days == 91
    assert result.threshold_days == 90


def test_stale_user_with_old_access_key_activity_is_flagged():
    current_time = datetime(
        2026, 9, 21, 12, 0, tzinfo=timezone.utc
    )
    last_activity_at = current_time - timedelta(days=120)

    result = check_stale_iam_user(
        username="alice",
        last_activity_at=last_activity_at,
        last_activity_type="access_key",
        last_activity_access_key_id="AKIAOLD123456789",
        current_time=current_time,
    )

    assert result is not None
    assert result.last_activity_type == "access_key"
    assert result.last_activity_access_key_id == "AKIAOLD123456789"
    assert result.age_days == 120


def test_recent_user_is_not_flagged():
    current_time = datetime(
        2026, 9, 21, 12, 0, tzinfo=timezone.utc
    )
    last_activity_at = current_time - timedelta(days=30)

    result = check_stale_iam_user(
        username="alice",
        last_activity_at=last_activity_at,
        last_activity_type="console_password",
        last_activity_access_key_id=None,
        current_time=current_time,
    )

    assert result is None


def test_exact_threshold_is_not_flagged():
    current_time = datetime(
        2026, 9, 21, 12, 0, tzinfo=timezone.utc
    )
    last_activity_at = current_time - timedelta(days=90)

    result = check_stale_iam_user(
        username="alice",
        last_activity_at=last_activity_at,
        last_activity_type="console_password",
        last_activity_access_key_id=None,
        current_time=current_time,
    )

    assert result is None


def test_user_with_no_known_activity_is_not_flagged():
    current_time = datetime(
        2026, 9, 21, 12, 0, tzinfo=timezone.utc
    )

    result = check_stale_iam_user(
        username="alice",
        last_activity_at=None,
        last_activity_type=None,
        last_activity_access_key_id=None,
        current_time=current_time,
    )

    assert result is None


def test_stale_user_finding_contains_expected_details():
    current_time = datetime(
        2026, 9, 21, 12, 0, tzinfo=timezone.utc
    )
    last_activity_at = current_time - timedelta(days=120)

    result = check_stale_iam_user(
        username="alice",
        last_activity_at=last_activity_at,
        last_activity_type="access_key",
        last_activity_access_key_id="AKIAOLD123456789",
        current_time=current_time,
    )

    assert result is not None

    finding = build_stale_iam_user_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-023"
    assert finding.title == "IAM User Is Stale"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"
    assert finding.evidence["username"] == "alice"
    assert finding.evidence["last_activity_type"] == "access_key"
    assert finding.evidence["age_days"] == 120
    assert finding.evidence["threshold_days"] == 90


def test_naive_datetimes_are_normalized_to_utc():
    current_time = datetime(2026, 9, 21, 12, 0)
    last_activity_at = datetime(2026, 6, 1, 12, 0)

    result = check_stale_iam_user(
        username="alice",
        last_activity_at=last_activity_at,
        last_activity_type="console_password",
        last_activity_access_key_id=None,
        current_time=current_time,
    )

    assert result is not None
    assert result.last_activity_at.tzinfo == timezone.utc
