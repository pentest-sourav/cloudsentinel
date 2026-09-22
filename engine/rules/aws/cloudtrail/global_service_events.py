from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailGlobalServiceEventsResult:
    trail_arn: str
    name: str | None
    include_global_service_events: bool


def check_cloudtrail_global_service_events(
    trail_arn: str,
    name: str | None,
    include_global_service_events: bool | None,
) -> CloudTrailGlobalServiceEventsResult | None:
    """
    Detect a CloudTrail trail that does not include global
    service events.
    """
    if include_global_service_events:
        return None

    return CloudTrailGlobalServiceEventsResult(
        trail_arn=trail_arn,
        name=name,
        include_global_service_events=False,
    )


def build_cloudtrail_global_service_events_finding(
    result: CloudTrailGlobalServiceEventsResult,
) -> Finding:
    """
    Build a finding for a CloudTrail trail that does not
    include global service events.
    """
    return Finding(
        rule_id="CS-AWS-CT-005",
        title="CloudTrail trail does not include global service events",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=(
            "The CloudTrail trail is not configured to include global "
            "service events. This can reduce visibility into activity "
            "from AWS services that operate globally rather than within "
            "a specific AWS region."
        ),
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "include_global_service_events": (
                result.include_global_service_events
            ),
        },
        remediation=(
            "Configure the CloudTrail trail to include global service "
            "events when centralized account-wide audit visibility "
            "is required."
        ),
        compliance=["CIS AWS Foundations"],
    )
