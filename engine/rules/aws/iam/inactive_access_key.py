from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class InactiveAccessKeyResult:
    username: str
    access_key_id: str
    status: str
    created_at: str


def check_inactive_access_key(
    username: str,
    access_key_id: str,
    status: str,
    created_at: str,
) -> InactiveAccessKeyResult | None:
    if status != "Inactive":
        return None

    return InactiveAccessKeyResult(
        username=username,
        access_key_id=access_key_id,
        status=status,
        created_at=created_at,
    )


def build_inactive_access_key_finding(
    result: InactiveAccessKeyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-004",
        title="IAM Access Key Is Inactive",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_access_key",
        resource_id=result.access_key_id,
        description=(
            f"The IAM access key '{result.access_key_id}' "
            f"belonging to user '{result.username}' is inactive."
        ),
        evidence={
            "username": result.username,
            "access_key_id": result.access_key_id,
            "status": result.status,
            "created_at": result.created_at,
        },
        remediation=(
            "Review the inactive access key and remove it if it is "
            "no longer required. If it is required for a workload, "
            "replace it with an actively managed credential."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
