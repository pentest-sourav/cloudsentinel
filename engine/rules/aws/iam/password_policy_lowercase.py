from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PasswordPolicyLowercaseResult:
    require_lowercase: bool


def check_password_policy_lowercase(
    require_lowercase: bool,
) -> PasswordPolicyLowercaseResult | None:
    if require_lowercase:
        return None

    return PasswordPolicyLowercaseResult(
        require_lowercase=require_lowercase,
    )


def build_password_policy_lowercase_finding(
    result: PasswordPolicyLowercaseResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-009",
        title="IAM Password Policy Does Not Require Lowercase Characters",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_password_policy",
        resource_id="account-password-policy",
        description=(
            "The IAM account password policy does not require "
            "users to include lowercase characters in their passwords."
        ),
        evidence={
            "require_lowercase": result.require_lowercase,
            "expected": True,
        },
        remediation=(
            "Enable the requirement for lowercase characters in "
            "the IAM account password policy."
        ),
        compliance=["CIS AWS Foundations"],
    )
