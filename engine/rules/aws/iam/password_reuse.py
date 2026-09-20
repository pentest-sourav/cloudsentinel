from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PasswordReuseResult:
    password_reuse_prevention: int


def check_password_reuse(
    password_reuse_prevention: int,
) -> PasswordReuseResult | None:
    if password_reuse_prevention >= 1:
        return None

    return PasswordReuseResult(
        password_reuse_prevention=password_reuse_prevention,
    )


def build_password_reuse_finding(
    result: PasswordReuseResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-010",
        title="IAM Password Policy Does Not Prevent Password Reuse",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_password_policy",
        resource_id="account-password-policy",
        description=(
            "The IAM account password policy does not prevent users "
            "from reusing previous passwords."
        ),
        evidence={
            "password_reuse_prevention": (
                result.password_reuse_prevention
            ),
            "expected": 1,
        },
        remediation=(
            "Configure password reuse prevention in the IAM account "
            "password policy by requiring users to remember previous "
            "passwords."
        ),
        compliance=["CIS AWS Foundations"],
    )
