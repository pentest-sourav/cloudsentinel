from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudFrontTaggingResult:
    resource_id: str
    tags: list[dict]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]

    @property
    def tagged(self) -> bool:
        return bool(self.tags)


def _normalize_required_tag_keys(
    required_tag_keys,
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


def _normalize_tags(tags) -> list[dict]:
    if not isinstance(tags, list):
        return []

    normalized: list[dict] = []

    for tag in tags:
        if not isinstance(tag, dict):
            continue

        key = tag.get("Key")

        if not isinstance(key, str) or not key.strip():
            continue

        if key.lower().startswith("aws:"):
            continue

        normalized.append(tag)

    return normalized


def _missing_required_tag_keys(
    tags: list[dict],
    required_tag_keys: list[str],
) -> list[str]:
    actual_keys = {
        tag.get("Key")
        for tag in tags
        if isinstance(tag.get("Key"), str)
    }

    return [
        key
        for key in required_tag_keys
        if key not in actual_keys
    ]


def check_cloudfront_tagging(
    resource_id: str,
    tags: list[dict],
    required_tag_keys=None,
) -> CloudFrontTaggingResult | None:
    if not resource_id:
        return None

    normalized_tags = _normalize_tags(tags)
    required = _normalize_required_tag_keys(
        required_tag_keys
    )

    if required:
        missing = _missing_required_tag_keys(
            normalized_tags,
            required,
        )

        if not missing:
            return None
    else:
        if normalized_tags:
            return None

        missing = []

    return CloudFrontTaggingResult(
        resource_id=resource_id,
        tags=normalized_tags,
        required_tag_keys=required,
        missing_tag_keys=missing,
    )


def build_cloudfront_tagging_finding(
    result: CloudFrontTaggingResult,
) -> Finding:
    if result.required_tag_keys:
        description = (
            f"The CloudFront distribution "
            f"{result.resource_id} is missing one or more "
            "required tag keys."
        )

        remediation = (
            "Add all configured required tag keys to the "
            "CloudFront distribution."
        )
    else:
        description = (
            f"The CloudFront distribution "
            f"{result.resource_id} has no non-system tags."
        )

        remediation = (
            "Add appropriate ownership, environment, "
            "application, or governance tags to the "
            "CloudFront distribution."
        )

    return Finding(
        rule_id="CS-AWS-CLOUDFRONT-014",
        title="CloudFront Distribution Is Not Properly Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="cloudfront_distribution",
        resource_id=result.resource_id,
        description=description,
        evidence={
            "resource_id": result.resource_id,
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=remediation,
        compliance=[
            "AWS Security Hub CloudFront.14",
        ],
    )
