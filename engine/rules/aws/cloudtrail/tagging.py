from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailTaggingResult:
    trail_arn: str
    name: str | None
    tags: list[dict[str, str]]

    @property
    def tagged(self) -> bool:
        return bool(self.tags)


def check_cloudtrail_tagging(
    trail_arn: str,
    name: str | None,
    tags: list[dict[str, str]],
) -> CloudTrailTaggingResult:
    """
    Evaluate whether a CloudTrail trail has at least one tag.
    """
    return CloudTrailTaggingResult(
        trail_arn=trail_arn,
        name=name,
        tags=tags,
    )


def build_cloudtrail_tagging_finding(
    result: CloudTrailTaggingResult,
) -> Finding | None:
    if result.tagged:
        return None

    return Finding(
        rule_id="CS-AWS-CT-009",
        title="CloudTrail trail is not tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=(
            "The CloudTrail trail does not have any tags. "
            "Tags help identify, organize, and manage CloudTrail "
            "resources consistently."
        ),
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "tags": result.tags,
            "tag_count": len(result.tags),
        },
        remediation=(
            "Add appropriate tags to the CloudTrail trail according "
            "to the organization's resource tagging requirements."
        ),
        compliance=[
            "AWS Resource Tagging Standard",
        ],
    )
