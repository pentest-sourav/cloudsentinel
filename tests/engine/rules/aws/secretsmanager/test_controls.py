from datetime import datetime, timedelta, timezone

from engine.findings.model import Severity

from engine.rules.aws.secretsmanager.automatic_rotation import (
    build_secretsmanager_automatic_rotation_finding,
    check_secretsmanager_automatic_rotation,
)
from engine.rules.aws.secretsmanager.rotation_period import (
    build_secretsmanager_rotation_period_finding,
    check_secretsmanager_rotation_period,
)
from engine.rules.aws.secretsmanager.tagging import (
    build_secretsmanager_tagging_finding,
    check_secretsmanager_tagging,
)
from engine.rules.aws.secretsmanager.unused_secret import (
    build_secretsmanager_unused_secret_finding,
    check_secretsmanager_unused_secret,
)


NOW = datetime.now(timezone.utc)


def test_automatic_rotation_passes_when_enabled():
    assert (
        check_secretsmanager_automatic_rotation(
            "secret-a",
            "arn:secret:a",
            True,
            {
                "AutomaticallyAfterDays": 30,
            },
        )
        is None
    )


def test_automatic_rotation_fails_when_disabled():
    result = check_secretsmanager_automatic_rotation(
        "secret-a",
        "arn:secret:a",
        False,
        {},
    )

    finding = (
        build_secretsmanager_automatic_rotation_finding(
            result
        )
    )

    assert (
        finding.rule_id
        == "CS-AWS-SECRETSMANAGER-001"
    )
    assert finding.severity == Severity.MEDIUM


def test_unused_secret_passes_when_recently_accessed():
    assert (
        check_secretsmanager_unused_secret(
            "secret-a",
            "arn:secret:a",
            NOW - timedelta(days=30),
        )
        is None
    )


def test_unused_secret_fails_after_default_window():
    result = check_secretsmanager_unused_secret(
        "secret-a",
        "arn:secret:a",
        NOW - timedelta(days=91),
    )

    finding = (
        build_secretsmanager_unused_secret_finding(
            result
        )
    )

    assert (
        finding.rule_id
        == "CS-AWS-SECRETSMANAGER-003"
    )
    assert finding.severity == Severity.MEDIUM


def test_unused_secret_fails_when_never_accessed():
    result = check_secretsmanager_unused_secret(
        "secret-a",
        "arn:secret:a",
        None,
    )

    assert result is not None


def test_rotation_period_passes_when_recent():
    assert (
        check_secretsmanager_rotation_period(
            "secret-a",
            "arn:secret:a",
            NOW - timedelta(days=30),
        )
        is None
    )


def test_rotation_period_fails_after_default_window():
    result = check_secretsmanager_rotation_period(
        "secret-a",
        "arn:secret:a",
        NOW - timedelta(days=91),
    )

    finding = (
        build_secretsmanager_rotation_period_finding(
            result
        )
    )

    assert (
        finding.rule_id
        == "CS-AWS-SECRETSMANAGER-004"
    )
    assert finding.severity == Severity.MEDIUM


def test_rotation_period_fails_when_never_rotated():
    result = check_secretsmanager_rotation_period(
        "secret-a",
        "arn:secret:a",
        None,
    )

    assert result is not None


def test_tagging_passes_with_non_system_tag():
    assert (
        check_secretsmanager_tagging(
            "secret-a",
            "arn:secret:a",
            [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        )
        is None
    )


def test_tagging_fails_with_only_system_tags():
    result = check_secretsmanager_tagging(
        "secret-a",
        "arn:secret:a",
        [
            {
                "Key": "aws:createdBy",
                "Value": "secretsmanager",
            }
        ],
    )

    finding = (
        build_secretsmanager_tagging_finding(
            result
        )
    )

    assert (
        finding.rule_id
        == "CS-AWS-SECRETSMANAGER-005"
    )
    assert finding.severity == Severity.LOW
