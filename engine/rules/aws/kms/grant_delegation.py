from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class KMSGrantDelegationResult:
    key_id: str
    grant_id: str | None
    grantee_principal: str | None
    operations: tuple[str, ...]


def _has_constraints(grant: dict[str, Any]) -> bool:
    constraints = grant.get("Constraints")
    return isinstance(constraints, dict) and bool(constraints)


def check_kms_grant_delegation(
    key_id: str,
    grants: list[dict[str, Any]] | None,
) -> KMSGrantDelegationResult | None:
    if not key_id or not grants:
        return None

    for grant in grants:
        if not isinstance(grant, dict):
            continue

        operations = grant.get("Operations")

        if not isinstance(operations, list):
            continue

        normalized_operations = tuple(
            sorted(
                {
                    operation
                    for operation in operations
                    if isinstance(operation, str)
                }
            )
        )

        if "CreateGrant" not in normalized_operations:
            continue

        if _has_constraints(grant):
            continue

        return KMSGrantDelegationResult(
            key_id=key_id,
            grant_id=grant.get("GrantId"),
            grantee_principal=grant.get("GranteePrincipal"),
            operations=normalized_operations,
        )

    return None


def build_kms_grant_delegation_finding(
    result: KMSGrantDelegationResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KMS-005",
        title="KMS Grant Allows Grant Creation Without Constraints",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="kms_key",
        resource_id=result.key_id,
        description=(
            f"A grant on KMS key {result.key_id} allows the grantee "
            "to create additional grants without a grant constraint. "
            "This can delegate further KMS access without an explicit "
            "resource or encryption-context restriction."
        ),
        evidence={
            "key_id": result.key_id,
            "grant_id": result.grant_id,
            "grantee_principal": result.grantee_principal,
            "operations": list(result.operations),
            "constraints_present": False,
        },
        remediation=(
            "Review whether CreateGrant is required. If it is required, "
            "restrict grant creation with appropriate grant constraints "
            "such as SourceArn or encryption-context constraints."
        ),
    )
