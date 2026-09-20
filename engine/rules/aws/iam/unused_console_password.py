from dataclasses import dataclass
from datetime import datetime, timezone

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class UnusedConsolePasswordResult:
    username: str
    password_enabled: bool
    password_last_used: datetime | None
    age_days: int | None
    threshold_days: int


def check_unused_console_password(
    username: str,
    password_enabled: bool,
    password_last_used: datetime | None,
    current_time: datetime,
    threshold_days: int = 90,
) -> UnusedConsolePasswordResult | None:
    if not password_enabled:
        return None

    if current_time.tzinfo is None:
        current_time = current_time.replace(
            tzinfo=timezone.utc
        )

    if password_last_used is None:
        return UnusedConsolePasswordResult(
            username=username,
            password_enabled=password_enabled,
            password_last_used=None,
            age_days=None,
            threshold_days=threshold_days,
        )

    if password_last_used.tzinfo is None:
        password_last_used = password_last_used.replace(
            tzinfo=timezone.utc
        )

    age_days = (
        current_time - password_last_used
    ).days

    if age_days <= threshold_days:
        return None

    return UnusedConsolePasswordResult(
        username=username,
        password_enabled=password_enabled,
        password_last_used=password_last_used,
        age_days=age_days,
        threshold_days=threshold_days,
    )


def build_unused_console_password_finding(
    result: UnusedConsolePasswordResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-011",
        title="IAM Console Password Has Not Been Used Recently",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"The IAM user '{result.username}' has an enabled "
            f"console password that has not been used for more than "
            f"{result.threshold_days} days."
        ),
        evidence={
            "username": result.username,
            "password_enabled": result.password_enabled,
            "password_last_used": (
                result.password_last_used.isoformat()
                if result.password_last_used is not None
                else None
            ),
            "age_days": result.age_days,
            "threshold_days": result.threshold_days,
        },
        remediation=(
            "Review whether the IAM user's console access is still "
            "required. If it is not required, remove the console "
            "password or otherwise disable unnecessary console access."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
