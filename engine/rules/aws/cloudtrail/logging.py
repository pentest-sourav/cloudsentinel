from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailLoggingResult:
    trail_arn: str
    name: str | None
    is_logging: bool


def check_cloudtrail_logging(
    trail_arn: str,
    name: str | None,
    is_logging: bool,
) -> CloudTrailLoggingResult | None:
    """
    Detect a CloudTrail trail that is not actively logging.
    """
    if is_logging:
        return None

    return CloudTrailLoggingResult(
        trail_arn=trail_arn,
        name=name,
        is_logging=is_logging,
    )


def build_cloudtrail_logging_finding(
    result: CloudTrailLoggingResult,
) -> Finding:
    """
    Build a security finding for a CloudTrail trail
    that is not actively logging.
    """
    return Finding(
        rule_id="CS-AWS-CT-001",
        title="CloudTrail trail is not actively logging",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=(
            "The CloudTrail trail is not actively logging events. "
            "Without active logging, security-relevant API activity "
            "may not be recorded for investigation, monitoring, "
            "and audit purposes."
        ),
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "is_logging": result.is_logging,
        },
        remediation=(
            "Enable logging for the affected CloudTrail trail and "
            "verify that events are being delivered successfully "
            "to the configured destination."
        ),
        compliance=["CIS AWS Foundations"],
    )
