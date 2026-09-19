from engine.findings.model import Severity
from engine.rules.aws.iam.inactive_access_key import (
    build_inactive_access_key_finding,
    check_inactive_access_key,
)


def test_inactive_access_key_is_flagged():
    result = check_inactive_access_key(
        username="test-user",
        access_key_id="AKIAINACTIVE123",
        status="Inactive",
        created_at="2026-01-01T00:00:00+00:00",
    )

    assert result is not None
    assert result.username == "test-user"
    assert result.access_key_id == "AKIAINACTIVE123"
    assert result.status == "Inactive"
    assert result.created_at == "2026-01-01T00:00:00+00:00"


def test_active_access_key_is_not_flagged():
    result = check_inactive_access_key(
        username="test-user",
        access_key_id="AKIAACTIVE123",
        status="Active",
        created_at="2026-01-01T00:00:00+00:00",
    )

    assert result is None


def test_inactive_access_key_finding_contains_expected_details():
    result = check_inactive_access_key(
        username="test-user",
        access_key_id="AKIAINACTIVE123",
        status="Inactive",
        created_at="2026-01-01T00:00:00+00:00",
    )

    finding = build_inactive_access_key_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-004"
    assert finding.title == "IAM Access Key Is Inactive"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_access_key"
    assert finding.resource_id == "AKIAINACTIVE123"


def test_inactive_access_key_finding_contains_expected_evidence():
    result = check_inactive_access_key(
        username="test-user",
        access_key_id="AKIAINACTIVE123",
        status="Inactive",
        created_at="2026-01-01T00:00:00+00:00",
    )

    finding = build_inactive_access_key_finding(result)

    assert finding.evidence["username"] == "test-user"
    assert finding.evidence["access_key_id"] == "AKIAINACTIVE123"
    assert finding.evidence["status"] == "Inactive"
    assert (
        finding.evidence["created_at"]
        == "2026-01-01T00:00:00+00:00"
    )
