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
    """
    Detect active IAM access keys that are older than the
    AWS IAM.3 rotation threshold.

    AWS IAM.3 checks whether active IAM access keys are rotated
    every 90 days or less.
    """
    if status != "Active":
        return None

    if created_at.tzinfo is None:
        created_at = created_at.replace(
            tzinfo=timezone.utc
        )

    if current_time.tzinfo is None:
        current_time = current_time.replace(
            tzinfo=timezone.utc
        )

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
        title="IAM User Access Key Exceeds 90-Day Rotation Period",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="aws_iam_user",
        resource_id=result.username,
        description=(
            f"IAM user '{result.username}' has an active access key "
            f"that is {result.age_days} days old, exceeding the "
            f"maximum recommended rotation period of "
            f"{result.threshold_days} days."
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
            "Rotate the IAM user's access key when it exceeds the "
            "90-day rotation period. Create the replacement key, "
            "update dependent applications and workloads, verify "
            "the replacement works, and then deactivate or remove "
            "the old key. Where possible, prefer IAM roles or "
            "federation instead of long-lived IAM user access keys."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
