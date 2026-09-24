from engine.findings.model import Severity
from engine.rules.aws.iam.password_policy_expiration import (
    PasswordPolicyExpirationResult,
    build_password_policy_expiration_finding,
    check_password_policy_expiration,
)


def test_password_expiration_passes_when_age_is_90_days():
    result = check_password_policy_expiration(90)

    assert result is None


def test_password_expiration_passes_when_age_is_less_than_90_days():
    result = check_password_policy_expiration(30)

    assert result is None


def test_password_expiration_fails_when_age_exceeds_90_days():
    result = check_password_policy_expiration(91)

    assert result == PasswordPolicyExpirationResult(
        max_password_age=91,
        threshold_days=90,
    )


def test_password_expiration_fails_when_expiration_is_disabled():
    result = check_password_policy_expiration(0)

    assert result == PasswordPolicyExpirationResult(
        max_password_age=0,
        threshold_days=90,
    )


def test_password_expiration_finding():
    result = PasswordPolicyExpirationResult(
        max_password_age=120,
        threshold_days=90,
    )

    finding = build_password_policy_expiration_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-039"
    assert finding.severity == Severity.LOW
    assert finding.resource_type == "iam_password_policy"
    assert finding.resource_id == "account-password-policy"
    assert finding.evidence == {
        "max_password_age": 120,
        "threshold_days": 90,
    }


def test_password_expiration_finding_for_disabled_expiration():
    result = PasswordPolicyExpirationResult(
        max_password_age=0,
        threshold_days=90,
    )

    finding = build_password_policy_expiration_finding(result)

    assert finding.rule_id == "CS-AWS-IAM-039"
    assert finding.severity == Severity.LOW
    assert finding.evidence["max_password_age"] == 0
