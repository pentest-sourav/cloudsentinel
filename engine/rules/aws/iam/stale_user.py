from dataclasses import dataclass
from datetime import datetime, timezone

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class StaleIAMUserResult:
    username: str
    last_activity_at: datetime
    last_activity_type: str
    last_activity_access_key_id: str | None
    age_days: int
    threshold_days: int


def check_stale_iam_user(
    username: str,
    last_activity_at: datetime | None,
    last_activity_type: str | None,
    last_activity_access_key_id: str | None,
    current_time: datetime,
    threshold_days: int = 90,
) -> StaleIAMUserResult | None:
    """
    Detect an IAM user whose latest known authentication activity
    is older than the configured stale-user threshold.
    """
    if last_activity_at is None:
        return None

    if not last_activity_type:
        return None

    if current_time.tzinfo is None:
        current_time = current_time.replace(
            tzinfo=timezone.utc
        )

    if last_activity_at.tzinfo is None:
        last_activity_at = last_activity_at.replace(
            tzinfo=timezone.utc
        )

    age_days = (
        current_time - last_activity_at
    ).days

    if age_days <= threshold_days:
        return None

    return StaleIAMUserResult(
        username=username,
        last_activity_at=last_activity_at,
        last_activity_type=last_activity_type,
        last_activity_access_key_id=(
            last_activity_access_key_id
        ),
        age_days=age_days,
        threshold_days=threshold_days,
    )


def build_stale_iam_user_finding(
    result: StaleIAMUserResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-023",
        title="IAM User Is Stale",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"The IAM user '{result.username}' has no recorded "
            f"authentication activity for more than "
            f"{result.threshold_days} days."
        ),
        evidence={
            "username": result.username,
            "last_activity_at": (
                result.last_activity_at.isoformat()
            ),
            "last_activity_type": result.last_activity_type,
            "last_activity_access_key_id": (
                result.last_activity_access_key_id
            ),
            "age_days": result.age_days,
            "threshold_days": result.threshold_days,
        },
        remediation=(
            "Review whether the IAM user is still required. If the "
            "identity is no longer needed, remove it according to "
            "your organization's identity lifecycle process. If the "
            "user is intentionally retained, document its owner, "
            "purpose, and business justification and review it "
            "periodically."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
