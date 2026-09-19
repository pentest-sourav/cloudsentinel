from engine.findings.model import Severity
from engine.rules.aws.iam.password_policy_symbols import (
    build_password_policy_symbols_finding,
    check_password_policy_symbols,
)


def test_password_policy_symbols_passes_when_symbols_are_required():
    result = check_password_policy_symbols(
        require_symbols=True,
    )

    assert result is None


def test_password_policy_symbols_fails_when_symbols_are_not_required():
    result = check_password_policy_symbols(
        require_symbols=False,
    )

    assert result is not None
    assert result.require_symbols is False


def test_password_policy_symbols_finding_has_expected_metadata():
    result = check_password_policy_symbols(
        require_symbols=False,
    )

    finding = build_password_policy_symbols_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-006"
    assert finding.severity == Severity.MEDIUM
    assert finding.provider == "aws"
    assert finding.resource_type == "iam_password_policy"
    assert finding.resource_id == "account-password-policy"


def test_password_policy_symbols_finding_contains_evidence_and_remediation():
    result = check_password_policy_symbols(
        require_symbols=False,
    )

    finding = build_password_policy_symbols_finding(result)

    assert finding.evidence == {
        "require_symbols": False,
        "expected": True,
    }
    assert "symbols" in finding.remediation.lower()
