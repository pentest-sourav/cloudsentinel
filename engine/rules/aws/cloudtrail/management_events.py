from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailManagementEventsResult:
    trail_arn: str
    name: str | None
    includes_management_events: bool


def check_cloudtrail_management_events(
    trail_arn: str,
    name: str | None,
    includes_management_events: bool,
) -> CloudTrailManagementEventsResult | None:
    """
    Detect a CloudTrail trail that does not include
    management events.
    """
    if includes_management_events:
        return None

    return CloudTrailManagementEventsResult(
        trail_arn=trail_arn,
        name=name,
        includes_management_events=False,
    )


def build_cloudtrail_management_events_finding(
    result: CloudTrailManagementEventsResult,
) -> Finding:
    """
    Build a finding for a CloudTrail trail that does not
    include management events.
    """
    return Finding(
        rule_id="CS-AWS-CT-007",
        title="CloudTrail trail does not include management events",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=(
            "The CloudTrail trail is not configured to include "
            "management events. Management events provide visibility "
            "into control-plane activity such as changes to AWS "
            "resources, permissions, and security configuration."
        ),
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "includes_management_events": (
                result.includes_management_events
            ),
        },
        remediation=(
            "Configure the CloudTrail trail to include management "
            "events so that AWS control-plane activity is recorded "
            "for security monitoring and audit purposes."
        ),
        compliance=["CIS AWS Foundations"],
    )
