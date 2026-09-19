from dataclasses import dataclass
from datetime import datetime, timezone

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class AccessKeyAgeResult:
    username: str
    access_key_id: str
    status: str
    created_at: datetime
    age_days: int
    threshold_days: int


def check_access_key_age(
    username: str,
    access_key_id: str,
    status: str,
    created_at: datetime,
    current_time: datetime,
    threshold_days: int = 90,
) -> AccessKeyAgeResult | None:
    if status != "Active":
        return None

    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)

    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)

    age_days = (current_time - created_at).days

    if age_days <= threshold_days:
        return None

    return AccessKeyAgeResult(
        username=username,
        access_key_id=access_key_id,
        status=status,
        created_at=created_at,
        age_days=age_days,
        threshold_days=threshold_days,
    )


def build_access_key_age_finding(
    result: AccessKeyAgeResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-003",
        title="IAM Access Key Exceeds Recommended Age",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_access_key",
        resource_id=result.access_key_id,
        description=(
            f"The active IAM access key for user '{result.username}' "
            f"is {result.age_days} days old, exceeding the recommended "
            f"maximum age of {result.threshold_days} days."
        ),
        evidence={
            "username": result.username,
            "access_key_id": result.access_key_id,
            "status": result.status,
            "created_at": result.created_at.isoformat(),
            "age_days": result.age_days,
            "threshold_days": result.threshold_days,
        },
        remediation=(
            "Rotate the IAM access key and remove the old key after "
            "verifying that dependent applications and workloads use "
            "the replacement credential."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
