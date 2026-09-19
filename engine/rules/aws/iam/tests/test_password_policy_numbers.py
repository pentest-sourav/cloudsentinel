from engine.findings.model import Severity
from engine.rules.aws.iam.password_policy_numbers import (
    build_password_policy_numbers_finding,
    check_password_policy_numbers,
)


def test_password_policy_numbers_passes_when_numbers_are_required():
    result = check_password_policy_numbers(
        require_numbers=True,
    )

    assert result is None


def test_password_policy_numbers_fails_when_numbers_are_not_required():
    result = check_password_policy_numbers(
        require_numbers=False,
    )

    assert result is not None
    assert result.require_numbers is False


def test_password_policy_numbers_finding_has_expected_metadata():
    result = check_password_policy_numbers(
        require_numbers=False,
    )

    finding = build_password_policy_numbers_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-007"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_password_policy"
    assert finding.resource_id == "account-password-policy"


def test_password_policy_numbers_finding_contains_evidence_and_remediation():
    result = check_password_policy_numbers(
        require_numbers=False,
    )

    finding = build_password_policy_numbers_finding(result)

    assert finding.evidence == {
        "require_numbers": False,
        "expected": True,
    }
    assert "numbers" in finding.remediation.lower()
