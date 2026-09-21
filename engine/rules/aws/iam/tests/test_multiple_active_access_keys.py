from engine.findings.model import Severity

from engine.rules.aws.iam.multiple_active_access_keys import (
    build_multiple_active_access_keys_finding,
    check_multiple_active_access_keys,
)


def test_detects_multiple_active_access_keys():
    result = check_multiple_active_access_keys(
        username="alice",
        active_access_key_count=2,
        active_access_key_ids=[
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    )

    assert result is not None
    assert result.username == "alice"
    assert result.active_access_key_count == 2
    assert result.active_access_key_ids == [
        "AKIAACTIVE001",
        "AKIAACTIVE002",
    ]


def test_does_not_detect_single_active_access_key():
    result = check_multiple_active_access_keys(
        username="alice",
        active_access_key_count=1,
        active_access_key_ids=[
            "AKIAACTIVE001",
        ],
    )

    assert result is None


def test_does_not_detect_zero_active_access_keys():
    result = check_multiple_active_access_keys(
        username="alice",
        active_access_key_count=0,
        active_access_key_ids=[],
    )

    assert result is None


def test_finding_has_expected_metadata():
    result = check_multiple_active_access_keys(
        username="alice",
        active_access_key_count=3,
        active_access_key_ids=[
            "AKIAACTIVE001",
            "AKIAACTIVE002",
            "AKIAACTIVE003",
        ],
    )

    finding = build_multiple_active_access_keys_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-IAM-017"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_user"
    assert finding.resource_id == "alice"


def test_finding_contains_active_key_evidence():
    result = check_multiple_active_access_keys(
        username="alice",
        active_access_key_count=2,
        active_access_key_ids=[
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    )

    finding = build_multiple_active_access_keys_finding(
        result
    )

    assert finding.evidence == {
        "username": "alice",
        "active_access_key_count": 2,
        "active_access_key_ids": [
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    }


def test_finding_contains_compliance():
    result = check_multiple_active_access_keys(
        username="alice",
        active_access_key_count=2,
        active_access_key_ids=[
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    )

    finding = build_multiple_active_access_keys_finding(
        result
    )

    assert finding.compliance == [
        "CIS AWS Foundations",
    ]
