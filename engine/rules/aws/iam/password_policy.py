from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PasswordPolicyResult:
    minimum_password_length: int
    threshold: int


def check_password_policy_minimum_length(
    minimum_password_length: int,
    threshold: int = 14,
) -> PasswordPolicyResult | None:
    if minimum_password_length >= threshold:
        return None

    return PasswordPolicyResult(
        minimum_password_length=minimum_password_length,
        threshold=threshold,
    )


def build_password_policy_finding(
    result: PasswordPolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-005",
        title="IAM Password Policy Minimum Length Is Too Short",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_password_policy",
        resource_id="account-password-policy",
        description=(
            "The IAM account password policy requires fewer than "
            f"{result.threshold} characters."
        ),
        evidence={
            "minimum_password_length": result.minimum_password_length,
            "threshold": result.threshold,
        },
        remediation=(
            "Increase the IAM account password policy minimum password "
            f"length to at least {result.threshold} characters."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
