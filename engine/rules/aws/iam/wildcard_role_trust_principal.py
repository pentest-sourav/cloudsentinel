from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


def _contains_wildcard_principal(
    principal: Any,
) -> bool:
    if principal == "*":
        return True

    if isinstance(principal, str):
        return False

    if isinstance(principal, (list, tuple, set)):
        return any(
            item == "*"
            for item in principal
        )

    if isinstance(principal, dict):
        for values in principal.values():
            if values == "*":
                return True

            if isinstance(values, (list, tuple, set)):
                if "*" in values:
                    return True

        return False

    return False


@dataclass(frozen=True)
class WildcardRoleTrustPrincipalResult:
    role_name: str
    role_arn: str
    statement_index: int
    effect: str
    principal: Any
    action: Any
    condition: Any


def check_wildcard_role_trust_principal(
    role_name: str,
    role_arn: str,
    statement_index: int,
    effect: str | None,
    principal: Any,
    action: Any,
    condition: Any,
) -> WildcardRoleTrustPrincipalResult | None:
    if effect != "Allow":
        return None

    if not _contains_wildcard_principal(principal):
        return None

    return WildcardRoleTrustPrincipalResult(
        role_name=role_name,
        role_arn=role_arn,
        statement_index=statement_index,
        effect=effect,
        principal=principal,
        action=action,
        condition=condition,
    )


def build_wildcard_role_trust_principal_finding(
    result: WildcardRoleTrustPrincipalResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-033",
        title="IAM Role Trust Policy Uses Wildcard Principal",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_role",
        resource_id=result.role_name,
        description=(
            f"IAM role '{result.role_name}' has an Allow trust "
            f"policy statement containing a wildcard Principal."
        ),
        evidence={
            "role_name": result.role_name,
            "role_arn": result.role_arn,
            "statement_index": result.statement_index,
            "effect": result.effect,
            "principal": result.principal,
            "action": result.action,
            "condition_present": bool(result.condition),
        },
        remediation=(
            "Replace the wildcard Principal with the smallest "
            "specific set of trusted AWS accounts, roles, users, "
            "or services required. Where appropriate, add "
            "restrictive trust-policy conditions."
        ),
        compliance=["CIS AWS Foundations"],
    )
