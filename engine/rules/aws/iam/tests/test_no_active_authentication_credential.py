from engine.findings.model import Severity
from engine.rules.aws.iam.no_active_authentication_credential import (
    build_no_active_authentication_credential_finding,
    check_no_active_authentication_credential,
)


def test_detects_user_without_password_or_active_access_key():
    result = check_no_active_authentication_credential(
        username="alice",
        password_enabled=False,
        active_access_key_count=0,
        active_access_key_ids=[],
    )

    assert result is not None
    assert result.username == "alice"
    assert result.password_enabled is False
    assert result.active_access_key_count == 0
    assert result.active_access_key_ids == []


def test_does_not_detect_user_with_console_password():
    result = check_no_active_authentication_credential(
        username="alice",
        password_enabled=True,
        active_access_key_count=0,
        active_access_key_ids=[],
    )

    assert result is None


def test_does_not_detect_user_with_active_access_key():
    result = check_no_active_authentication_credential(
        username="alice",
        password_enabled=False,
        active_access_key_count=1,
        active_access_key_ids=[
            "AKIAACTIVE001",
        ],
    )

    assert result is None


def test_does_not_detect_user_with_password_and_active_access_key():
    result = check_no_active_authentication_credential(
        username="alice",
        password_enabled=True,
        active_access_key_count=1,
        active_access_key_ids=[
            "AKIAACTIVE001",
        ],
    )

    assert result is None


def test_finding_has_expected_metadata():
    result = check_no_active_authentication_credential(
        username="alice",
        password_enabled=False,
        active_access_key_count=0,
        active_access_key_ids=[],
    )

    assert result is not None

    finding = build_no_active_authentication_credential_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-020"
    assert finding.title == (
        "IAM User Has No Active Authentication Credential"
    )
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"


def test_finding_contains_expected_evidence():
    result = check_no_active_authentication_credential(
        username="alice",
        password_enabled=False,
        active_access_key_count=0,
        active_access_key_ids=[],
    )

    assert result is not None

    finding = build_no_active_authentication_credential_finding(
        result
    )

    assert finding.evidence == {
        "username": "alice",
        "password_enabled": False,
        "active_access_key_count": 0,
        "active_access_key_ids": [],
        "has_active_authentication_credential": False,
    }


def test_finding_contains_compliance():
    result = check_no_active_authentication_credential(
        username="alice",
        password_enabled=False,
        active_access_key_count=0,
        active_access_key_ids=[],
    )

    assert result is not None

    finding = build_no_active_authentication_credential_finding(
        result
    )

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]
