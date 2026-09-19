from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PasswordPolicySymbolsResult:
    require_symbols: bool


def check_password_policy_symbols(
    require_symbols: bool,
) -> PasswordPolicySymbolsResult | None:
    if require_symbols:
        return None

    return PasswordPolicySymbolsResult(
        require_symbols=require_symbols,
    )


def build_password_policy_symbols_finding(
    result: PasswordPolicySymbolsResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-006",
        title="IAM Password Policy Does Not Require Symbols",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_password_policy",
        resource_id="account-password-policy",
        description=(
            "The IAM account password policy does not require "
            "users to include symbols in their passwords."
        ),
        evidence={
            "require_symbols": result.require_symbols,
            "expected": True,
        },
        remediation=(
            "Enable the requirement for symbols in the IAM account "
            "password policy."
        ),
        compliance=["CIS AWS Foundations"],
    )
