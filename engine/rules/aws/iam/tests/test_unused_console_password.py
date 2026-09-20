from datetime import datetime, timezone

from engine.findings.model import Severity
from engine.rules.aws.iam.unused_console_password import (
    UnusedConsolePasswordResult,
    build_unused_console_password_finding,
    check_unused_console_password,
)


def test_password_unused_for_more_than_90_days_returns_finding():
    current_time = datetime(
        2026,
        9,
        20,
        tzinfo=timezone.utc,
    )

    password_last_used = datetime(
        2026,
        6,
        1,
        tzinfo=timezone.utc,
    )

    result = check_unused_console_password(
        username="alice",
        password_enabled=True,
        password_last_used=password_last_used,
        current_time=current_time,
    )

    assert isinstance(
        result,
        UnusedConsolePasswordResult,
    )

    assert result.username == "alice"
    assert result.age_days > 90
    assert result.threshold_days == 90


def test_password_used_within_90_days_returns_none():
    current_time = datetime(
        2026,
        9,
        20,
        tzinfo=timezone.utc,
    )

    password_last_used = datetime(
        2026,
        9,
        1,
        tzinfo=timezone.utc,
    )

    result = check_unused_console_password(
        username="alice",
        password_enabled=True,
        password_last_used=password_last_used,
        current_time=current_time,
    )

    assert result is None


def test_disabled_console_password_returns_none():
    current_time = datetime(
        2026,
        9,
        20,
        tzinfo=timezone.utc,
    )

    password_last_used = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    result = check_unused_console_password(
        username="alice",
        password_enabled=False,
        password_last_used=password_last_used,
        current_time=current_time,
    )

    assert result is None


def test_never_used_console_password_returns_finding():
    current_time = datetime(
        2026,
        9,
        20,
        tzinfo=timezone.utc,
    )

    result = check_unused_console_password(
        username="alice",
        password_enabled=True,
        password_last_used=None,
        current_time=current_time,
    )

    assert isinstance(
        result,
        UnusedConsolePasswordResult,
    )

    assert result.username == "alice"
    assert result.password_last_used is None
    assert result.age_days is None


def test_build_unused_console_password_finding():
    result = UnusedConsolePasswordResult(
        username="alice",
        password_enabled=True,
        password_last_used=datetime(
            2026,
            1,
            1,
            tzinfo=timezone.utc,
        ),
        age_days=262,
        threshold_days=90,
    )

    finding = build_unused_console_password_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-011"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"

    assert finding.evidence["username"] == "alice"
    assert finding.evidence["password_enabled"] is True
    assert finding.evidence["age_days"] == 262
    assert finding.evidence["threshold_days"] == 90
