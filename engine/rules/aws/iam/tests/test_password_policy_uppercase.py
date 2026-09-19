from engine.findings.model import Severity
from engine.rules.aws.iam.password_policy_uppercase import (
    build_password_policy_uppercase_finding,
    check_password_policy_uppercase,
)


def test_password_policy_uppercase_passes_when_uppercase_is_required():
    result = check_password_policy_uppercase(
        require_uppercase=True,
    )

    assert result is None


def test_password_policy_uppercase_fails_when_uppercase_is_not_required():
    result = check_password_policy_uppercase(
        require_uppercase=False,
    )

    assert result is not None
    assert result.require_uppercase is False


def test_password_policy_uppercase_finding_has_expected_metadata():
    result = check_password_policy_uppercase(
        require_uppercase=False,
    )

    finding = build_password_policy_uppercase_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-008"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_password_policy"
    assert finding.resource_id == "account-password-policy"


def test_password_policy_uppercase_finding_contains_evidence_and_remediation():
    result = check_password_policy_uppercase(
        require_uppercase=False,
    )

    finding = build_password_policy_uppercase_finding(result)

    assert finding.evidence == {
        "require_uppercase": False,
        "expected": True,
    }
    assert "uppercase" in finding.remediation.lower()
