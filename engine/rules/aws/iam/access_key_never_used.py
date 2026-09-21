from dataclasses import dataclass
from datetime import datetime

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AccessKeyNeverUsedResult:
    username: str
    access_key_id: str
    status: str
    last_used_at: datetime | None


def check_access_key_never_used(
    username: str,
    access_key_id: str,
    status: str,
    last_used_at: datetime | None,
) -> AccessKeyNeverUsedResult | None:
    if status != "Active":
        return None

    if last_used_at is not None:
        return None

    return AccessKeyNeverUsedResult(
        username=username,
        access_key_id=access_key_id,
        status=status,
        last_used_at=last_used_at,
    )


def build_access_key_never_used_finding(
    result: AccessKeyNeverUsedResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-019",
        title="IAM Active Access Key Has Never Been Used",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_access_key",
        resource_id=result.access_key_id,
        description=(
            f"The active IAM access key '{result.access_key_id}' "
            f"belonging to user '{result.username}' has no recorded "
            "last-used timestamp. The credential may be unnecessary "
            "and increases the account's credential attack surface."
        ),
        evidence={
            "username": result.username,
            "access_key_id": result.access_key_id,
            "status": result.status,
            "last_used_at": result.last_used_at,
            "never_used": True,
        },
        remediation=(
            "Verify whether the access key is required. If it is "
            "unused and no longer needed, deactivate and remove it. "
            "If it is required but has not yet been used, document "
            "its purpose and review the credential again periodically."
        ),
        compliance=["CIS AWS Foundations"],
    )
