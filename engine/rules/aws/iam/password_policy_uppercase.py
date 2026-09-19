from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PasswordPolicyUppercaseResult:
    require_uppercase: bool


def check_password_policy_uppercase(
    require_uppercase: bool,
) -> PasswordPolicyUppercaseResult | None:
    if require_uppercase:
        return None

    return PasswordPolicyUppercaseResult(
        require_uppercase=require_uppercase,
    )


def build_password_policy_uppercase_finding(
    result: PasswordPolicyUppercaseResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-008",
        title="IAM Password Policy Does Not Require Uppercase Characters",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_password_policy",
        resource_id="account-password-policy",
        description=(
            "The IAM account password policy does not require "
            "users to include uppercase characters in their passwords."
        ),
        evidence={
            "require_uppercase": result.require_uppercase,
            "expected": True,
        },
        remediation=(
            "Enable the requirement for uppercase characters in "
            "the IAM account password policy."
        ),
        compliance=["CIS AWS Foundations"],
    )
