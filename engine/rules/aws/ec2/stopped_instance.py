from dataclasses import dataclass
from datetime import datetime, timezone


DEFAULT_ALLOWED_DAYS = 30


@dataclass(frozen=True)
class StoppedInstanceResult:
    """
    Result of evaluating a stopped EC2 instance.
    """

    instance_id: str
    stopped_since: datetime
    allowed_days: int
    stopped_days: int


def _calculate_stopped_since(
    state_transition_reason: str | None,
) -> datetime | None:
    """
    Extract the stop timestamp from AWS StateTransitionReason.

    AWS commonly returns:
        User initiated (2026-09-23 10:30:00 GMT)

    The launch time is intentionally not used as a fallback because
    it represents instance creation time, not the time at which the
    instance entered the stopped state.
    """
    if not state_transition_reason:
        return None

    start = state_transition_reason.find("(")
    end = state_transition_reason.find(")")

    if start == -1 or end <= start:
        return None

    timestamp = state_transition_reason[
        start + 1:end
    ].strip()

    try:
        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S %Z",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def check_stopped_instance(
    instance_id: str,
    instance_state: str | None,
    launch_time: datetime | None,
    state_transition_reason: str | None,
    allowed_days: int = DEFAULT_ALLOWED_DAYS,
    now: datetime | None = None,
) -> StoppedInstanceResult | None:
    """
    Detect an EC2 instance that has remained stopped longer
    than the configured threshold.

    Default threshold:
        30 days
    """
    if instance_state != "stopped":
        return None

    stopped_since = _calculate_stopped_since(
        state_transition_reason,
    )

    if stopped_since is None:
        return None

    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    stopped_days = max(
        0,
        (now - stopped_since).days,
    )

    if stopped_days <= allowed_days:
        return None

    return StoppedInstanceResult(
        instance_id=instance_id,
        stopped_since=stopped_since,
        allowed_days=allowed_days,
        stopped_days=stopped_days,
    )


def build_stopped_instance_finding(
    result: StoppedInstanceResult,
):
    from engine.findings.model import Finding, Severity

    return Finding(
        rule_id="CS-AWS-EC2-010",
        title="EC2 Instance Has Been Stopped Too Long",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ec2_instance",
        resource_id=result.instance_id,
        description=(
            f"The EC2 instance {result.instance_id} has remained "
            f"stopped for approximately {result.stopped_days} days, "
            f"which exceeds the configured {result.allowed_days}-day "
            "threshold. Long-stopped instances may not receive "
            "regular patching or security maintenance."
        ),
        evidence={
            "instance_id": result.instance_id,
            "stopped_since": result.stopped_since.isoformat(),
            "stopped_days": result.stopped_days,
            "allowed_days": result.allowed_days,
        },
        remediation=(
            "Review the stopped instance and either terminate it "
            "if it is no longer required or start it periodically "
            "to perform operating-system and application maintenance."
        ),
        compliance=[
            "AWS Security Hub EC2.4",
        ],
    )
