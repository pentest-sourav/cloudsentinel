from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailNoTrailResult:
    trail_count: int


def check_cloudtrail_no_trail(
    trail_count: int,
) -> CloudTrailNoTrailResult | None:
    if trail_count > 0:
        return None

    return CloudTrailNoTrailResult(
        trail_count=trail_count,
    )


def build_cloudtrail_no_trail_finding(
    result: CloudTrailNoTrailResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-CT-002",
        title="No CloudTrail trail is configured",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="cloudtrail",
        resource_id="aws-account",
        description=(
            "No CloudTrail trail is configured for the AWS account. "
            "Without a configured trail, API activity may not be "
            "persistently recorded for security investigation, "
            "monitoring, and audit purposes."
        ),
        evidence={
            "trail_count": result.trail_count,
        },
        remediation=(
            "Configure an AWS CloudTrail trail and enable logging. "
            "Use an appropriate centralized S3 destination and "
            "enable log file validation where required."
        ),
        compliance=["CIS AWS Foundations"],
    )
