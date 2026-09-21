from engine.findings.model import Severity

from engine.rules.aws.iam.multiple_authentication_methods import (
    build_multiple_authentication_methods_finding,
    check_multiple_authentication_methods,
)


def test_detects_multiple_authentication_methods():
    result = check_multiple_authentication_methods(
        username="alice",
        password_enabled=True,
        active_access_key_count=1,
        active_access_key_ids=[
            "AKIAACTIVE001",
        ],
    )

    assert result is not None
    assert result.username == "alice"
    assert result.password_enabled is True
    assert result.active_access_key_count == 1
    assert result.active_access_key_ids == [
        "AKIAACTIVE001",
    ]


def test_detects_password_with_multiple_active_access_keys():
    result = check_multiple_authentication_methods(
        username="alice",
        password_enabled=True,
        active_access_key_count=2,
        active_access_key_ids=[
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    )

    assert result is not None
    assert result.active_access_key_count == 2


def test_does_not_detect_when_password_is_disabled():
    result = check_multiple_authentication_methods(
        username="alice",
        password_enabled=False,
        active_access_key_count=1,
        active_access_key_ids=[
            "AKIAACTIVE001",
        ],
    )

    assert result is None


def test_does_not_detect_without_active_access_key():
    result = check_multiple_authentication_methods(
        username="alice",
        password_enabled=True,
        active_access_key_count=0,
        active_access_key_ids=[],
    )

    assert result is None


def test_finding_has_expected_metadata():
    result = check_multiple_authentication_methods(
        username="alice",
        password_enabled=True,
        active_access_key_count=2,
        active_access_key_ids=[
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    )

    finding = build_multiple_authentication_methods_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-018"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"


def test_finding_contains_expected_evidence():
    result = check_multiple_authentication_methods(
        username="alice",
        password_enabled=True,
        active_access_key_count=2,
        active_access_key_ids=[
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    )

    finding = build_multiple_authentication_methods_finding(
        result
    )

    assert finding.evidence == {
        "username": "alice",
        "password_enabled": True,
        "active_access_key_count": 2,
        "active_access_key_ids": [
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    }


def test_finding_contains_compliance():
    result = check_multiple_authentication_methods(
        username="alice",
        password_enabled=True,
        active_access_key_count=1,
        active_access_key_ids=[
            "AKIAACTIVE001",
        ],
    )

    finding = build_multiple_authentication_methods_finding(
        result
    )

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]
