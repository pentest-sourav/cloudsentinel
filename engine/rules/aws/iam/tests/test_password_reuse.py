from engine.findings.model import Severity
from engine.rules.aws.iam.password_reuse import (
    PasswordReuseResult,
    build_password_reuse_finding,
    check_password_reuse,
)


def test_password_reuse_passes_when_previous_passwords_are_restricted():
    result = check_password_reuse(24)

    assert result is None


def test_password_reuse_fails_when_reuse_prevention_is_zero():
    result = check_password_reuse(0)

    assert result == PasswordReuseResult(
        password_reuse_prevention=0,
    )


def test_password_reuse_finding_contains_expected_details():
    result = PasswordReuseResult(
        password_reuse_prevention=0,
    )

    finding = build_password_reuse_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-010"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_password_policy"
    assert finding.resource_id == "account-password-policy"

    assert finding.evidence == {
        "password_reuse_prevention": 0,
        "expected": 1,
    }


def test_password_reuse_finding_contains_remediation():
    result = PasswordReuseResult(
        password_reuse_prevention=0,
    )

    finding = build_password_reuse_finding(result)

    assert "password reuse prevention" in finding.remediation.lower()
    assert "CIS AWS Foundations" in finding.compliance
