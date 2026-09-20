from engine.findings.model import Severity
from engine.rules.aws.iam.password_policy_lowercase import (
    build_password_policy_lowercase_finding,
    check_password_policy_lowercase,
)


def test_password_policy_lowercase_passes_when_lowercase_is_required():
    result = check_password_policy_lowercase(
        require_lowercase=True,
    )
    assert result is None


def test_password_policy_lowercase_fails_when_lowercase_is_not_required():
    result = check_password_policy_lowercase(
        require_lowercase=False,
    )
    assert result is not None
    assert result.require_lowercase is False


def test_password_policy_lowercase_finding_has_expected_metadata():
    result = check_password_policy_lowercase(
        require_lowercase=False,
    )
    finding = build_password_policy_lowercase_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-009"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_password_policy"
    assert finding.resource_id == "account-password-policy"


def test_password_policy_lowercase_finding_contains_evidence_and_remediation():
    result = check_password_policy_lowercase(
        require_lowercase=False,
    )
    finding = build_password_policy_lowercase_finding(result)

    assert finding.evidence == {
        "require_lowercase": False,
        "expected": True,
    }
    assert "lowercase" in finding.remediation.lower()
