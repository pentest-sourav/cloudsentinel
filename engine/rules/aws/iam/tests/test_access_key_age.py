from datetime import datetime, timezone

from engine.findings.model import Severity
from engine.rules.aws.iam.access_key_age import (
    build_access_key_age_finding,
    check_access_key_age,
)


def test_detects_active_access_key_older_than_90_days():
    current_time = datetime(
        2026,
        9,
        21,
        tzinfo=timezone.utc,
    )

    created_at = datetime(
        2026,
        6,
        20,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="alice",
        access_key_id="AKIAEXAMPLE",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is not None
    assert result.username == "alice"
    assert result.access_key_id == "AKIAEXAMPLE"
    assert result.age_days > 90
    assert result.threshold_days == 90


def test_does_not_detect_access_key_at_exactly_90_days():
    current_time = datetime(
        2026,
        9,
        21,
        tzinfo=timezone.utc,
    )

    created_at = datetime(
        2026,
        6,
        23,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="alice",
        access_key_id="AKIAEXAMPLE",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is None


def test_does_not_detect_recent_active_access_key():
    current_time = datetime(
        2026,
        9,
        21,
        tzinfo=timezone.utc,
    )

    created_at = datetime(
        2026,
        8,
        1,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="alice",
        access_key_id="AKIAEXAMPLE",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is None


def test_does_not_detect_inactive_access_key():
    current_time = datetime(
        2026,
        9,
        21,
        tzinfo=timezone.utc,
    )

    created_at = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="alice",
        access_key_id="AKIAEXAMPLE",
        status="Inactive",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is None


def test_handles_naive_datetimes():
    current_time = datetime(
        2026,
        9,
        21,
    )

    created_at = datetime(
        2026,
        1,
        1,
    )

    result = check_access_key_age(
        username="alice",
        access_key_id="AKIAEXAMPLE",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is not None
    assert result.created_at.tzinfo == timezone.utc


def test_finding_matches_aws_iam3_metadata():
    current_time = datetime(
        2026,
        9,
        21,
        tzinfo=timezone.utc,
    )

    created_at = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="alice",
        access_key_id="AKIAEXAMPLE",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is not None

    finding = build_access_key_age_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-003"
    assert finding.title == (
        "IAM User Access Key Exceeds 90-Day Rotation Period"
    )
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "aws_iam_user"
    assert finding.resource_id == "alice"


def test_finding_contains_access_key_evidence():
    current_time = datetime(
        2026,
        9,
        21,
        tzinfo=timezone.utc,
    )

    created_at = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="alice",
        access_key_id="AKIAEXAMPLE",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is not None

    finding = build_access_key_age_finding(result)

    assert finding.evidence["username"] == "alice"
    assert finding.evidence["access_key_id"] == "AKIAEXAMPLE"
    assert finding.evidence["status"] == "Active"
    assert finding.evidence["threshold_days"] == 90
    assert finding.evidence["age_days"] > 90


def test_finding_contains_cis_compliance():
    current_time = datetime(
        2026,
        9,
        21,
        tzinfo=timezone.utc,
    )

    created_at = datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    result = check_access_key_age(
        username="alice",
        access_key_id="AKIAEXAMPLE",
        status="Active",
        created_at=created_at,
        current_time=current_time,
    )

    assert result is not None

    finding = build_access_key_age_finding(result)

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]
