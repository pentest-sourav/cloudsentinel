from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailTaggingResult:
    trail_arn: str
    name: str | None
    tags: list[dict[str, str]]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]

    @property
    def tagged(self) -> bool:
        return bool(self.tags)


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    normalized: list[str] = []

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue

        key = key.strip()

        if not key or key.lower().startswith("aws:"):
            continue

        if key not in normalized:
            normalized.append(key)

    return normalized


def _missing_required_tag_keys(
    tags: list[dict[str, str]] | None,
    required_tag_keys: list[str],
) -> list[str]:
    present_keys: set[str] = set()

    for tag in tags or []:
        if not isinstance(tag, dict):
            continue

        key = tag.get("Key")

        if not isinstance(key, str):
            continue

        key = key.strip()

        if not key or key.lower().startswith("aws:"):
            continue

        present_keys.add(key)

    return [
        key
        for key in required_tag_keys
        if key not in present_keys
    ]


def check_cloudtrail_tagging(
    trail_arn: str,
    name: str | None,
    tags: list[dict[str, str]],
    required_tag_keys: list[str] | None = None,
) -> CloudTrailTaggingResult:
    """
    Evaluate whether a CloudTrail trail satisfies its tagging
    requirements.

    When required_tag_keys is configured, every configured key must
    be present using exact, case-sensitive matching.

    When no required keys are configured, preserve the original
    baseline behavior of requiring at least one non-system tag.
    """
    normalized_required_keys = _normalize_required_tag_keys(
        required_tag_keys
    )

    missing_tag_keys = _missing_required_tag_keys(
        tags,
        normalized_required_keys,
    )

    return CloudTrailTaggingResult(
        trail_arn=trail_arn,
        name=name,
        tags=tags,
        required_tag_keys=normalized_required_keys,
        missing_tag_keys=missing_tag_keys,
    )


def build_cloudtrail_tagging_finding(
    result: CloudTrailTaggingResult,
) -> Finding | None:
    if result.required_tag_keys:
        compliant = not result.missing_tag_keys
    else:
        compliant = result.tagged

    if compliant:
        return None

    if result.required_tag_keys:
        description = (
            "The CloudTrail trail is missing one or more required "
            "tag keys configured for this control."
        )
        remediation = (
            "Add all required tags to the CloudTrail trail. "
            "Required tag keys are matched case-sensitively."
        )
    else:
        description = (
            "The CloudTrail trail does not have any tags. "
            "Tags help identify, organize, and manage CloudTrail "
            "resources consistently."
        )
        remediation = (
            "Add appropriate tags to the CloudTrail trail according "
            "to the organization's resource tagging requirements."
        )

    return Finding(
        rule_id="CS-AWS-CT-009",
        title="CloudTrail trail is not tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=description,
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "tags": result.tags,
            "tag_count": len(result.tags),
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=remediation,
        compliance=[
            "AWS Resource Tagging Standard",
        ],
    )
