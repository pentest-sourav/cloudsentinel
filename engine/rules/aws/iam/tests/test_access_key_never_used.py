from datetime import datetime, timezone

from engine.findings.model import Severity
from engine.rules.aws.iam.access_key_never_used import (
    build_access_key_never_used_finding,
    check_access_key_never_used,
)


def test_active_access_key_that_has_never_been_used_is_flagged():
    result = check_access_key_never_used(
        username="test-user",
        access_key_id="AKIANEVERUSED123",
        status="Active",
        last_used_at=None,
    )

    assert result is not None
    assert result.username == "test-user"
    assert result.access_key_id == "AKIANEVERUSED123"
    assert result.status == "Active"
    assert result.last_used_at is None


def test_inactive_access_key_that_has_never_been_used_is_not_flagged():
    result = check_access_key_never_used(
        username="test-user",
        access_key_id="AKIAINACTIVE123",
        status="Inactive",
        last_used_at=None,
    )

    assert result is None


def test_active_access_key_that_was_previously_used_is_not_flagged():
    last_used_at = datetime(
        2026,
        9,
        1,
        12,
        30,
        tzinfo=timezone.utc,
    )

    result = check_access_key_never_used(
        username="test-user",
        access_key_id="AKIAUSED123",
        status="Active",
        last_used_at=last_used_at,
    )

    assert result is None


def test_access_key_never_used_finding_contains_expected_details():
    result = check_access_key_never_used(
        username="test-user",
        access_key_id="AKIANEVERUSED123",
        status="Active",
        last_used_at=None,
    )

    assert result is not None

    finding = build_access_key_never_used_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-019"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_access_key"
    assert finding.resource_id == "AKIANEVERUSED123"

    assert finding.evidence["username"] == "test-user"
    assert finding.evidence["access_key_id"] == "AKIANEVERUSED123"
    assert finding.evidence["status"] == "Active"
    assert finding.evidence["last_used_at"] is None
    assert finding.evidence["never_used"] is True

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]
