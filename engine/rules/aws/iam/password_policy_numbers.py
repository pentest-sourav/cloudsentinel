from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PasswordPolicyNumbersResult:
    require_numbers: bool


def check_password_policy_numbers(
    require_numbers: bool,
) -> PasswordPolicyNumbersResult | None:
    if require_numbers:
        return None

    return PasswordPolicyNumbersResult(
        require_numbers=require_numbers,
    )


def build_password_policy_numbers_finding(
    result: PasswordPolicyNumbersResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-007",
        title="IAM Password Policy Does Not Require Numbers",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_password_policy",
        resource_id="account-password-policy",
        description=(
            "The IAM account password policy does not require "
            "users to include numbers in their passwords."
        ),
        evidence={
            "require_numbers": result.require_numbers,
            "expected": True,
        },
        remediation=(
            "Enable the requirement for numbers in the IAM account "
            "password policy."
        ),
        compliance=["CIS AWS Foundations"],
    )
