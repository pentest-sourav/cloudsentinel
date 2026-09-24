from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PasswordPolicyExpirationResult:
    max_password_age: int
    threshold_days: int


def check_password_policy_expiration(
    max_password_age: int,
    threshold_days: int = 90,
) -> PasswordPolicyExpirationResult | None:
    if 1 <= max_password_age <= threshold_days:
        return None

    return PasswordPolicyExpirationResult(
        max_password_age=max_password_age,
        threshold_days=threshold_days,
    )


def build_password_policy_expiration_finding(
    result: PasswordPolicyExpirationResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-039",
        title="IAM Password Policy Does Not Expire Passwords Within 90 Days",
        severity=Severity.LOW,
        provider="aws",
        resource_type="iam_password_policy",
        resource_id="account-password-policy",
        description=(
            "The IAM account password policy does not require passwords "
            f"to expire within {result.threshold_days} days."
        ),
        evidence={
            "max_password_age": result.max_password_age,
            "threshold_days": result.threshold_days,
        },
        remediation=(
            "Configure the IAM account password policy to expire "
            f"passwords within {result.threshold_days} days or less."
        ),
        compliance=[
            "CIS AWS Foundations v1.2.0/1.11",
        ],
    )
