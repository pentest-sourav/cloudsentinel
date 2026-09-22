from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailMultiRegionResult:
    trail_arn: str
    name: str | None
    is_multi_region_trail: bool


def check_cloudtrail_multi_region(
    trail_arn: str,
    name: str | None,
    is_multi_region_trail: bool | None,
) -> CloudTrailMultiRegionResult | None:
    """
    Detect a CloudTrail trail that is not configured as multi-region.
    """
    if is_multi_region_trail:
        return None

    return CloudTrailMultiRegionResult(
        trail_arn=trail_arn,
        name=name,
        is_multi_region_trail=False,
    )


def build_cloudtrail_multi_region_finding(
    result: CloudTrailMultiRegionResult,
) -> Finding:
    """
    Build a finding for a CloudTrail trail that is not
    configured as a multi-region trail.
    """
    return Finding(
        rule_id="CS-AWS-CT-004",
        title="CloudTrail trail is not configured as multi-region",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=(
            "The CloudTrail trail is not configured as a multi-region "
            "trail. A single-region trail may provide incomplete "
            "visibility into API activity occurring in other AWS "
            "regions."
        ),
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "is_multi_region_trail": result.is_multi_region_trail,
        },
        remediation=(
            "Configure the CloudTrail trail as a multi-region trail "
            "when centralized account-wide audit visibility is required."
        ),
        compliance=["CIS AWS Foundations"],
    )
