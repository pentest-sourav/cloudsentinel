from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class IAMTaggingResult:
    rule_id: str
    resource_type: str
    resource_id: str
    title: str
    tags: list[dict[str, Any]]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]


def _non_system_tags(
    tags: list[dict[str, Any]] | dict[str, str],
) -> list[dict[str, Any]]:
    if isinstance(tags, dict):
        return [
            {
                "Key": key,
                "Value": value,
            }
            for key, value in tags.items()
            if not str(key).startswith("aws:")
        ]

    return [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and not str(tag.get("Key", "")).startswith("aws:")
    ]


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | tuple[str, ...] | None,
) -> list[str]:
    normalized: list[str] = []

    if not isinstance(required_tag_keys, (list, tuple)):
        return normalized

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue

        key = key.strip()

        if not key or key.lower().startswith("aws:"):
            continue

        if key not in normalized:
            normalized.append(key)

    return normalized


def check_iam_tagging(
    rule_id: str,
    resource_type: str,
    resource_id: str,
    title: str,
    tags: list[dict[str, Any]] | dict[str, str],
    required_tag_keys: list[str] | tuple[str, ...] | None = None,
) -> IAMTaggingResult | None:
    user_tags = _non_system_tags(tags)
    normalized_required_keys = _normalize_required_tag_keys(
        required_tag_keys
    )

    actual_tag_keys = {
        str(tag.get("Key"))
        for tag in user_tags
        if isinstance(tag, dict)
        and tag.get("Key")
    }

    if normalized_required_keys:
        missing_tag_keys = [
            key
            for key in normalized_required_keys
            if key not in actual_tag_keys
        ]

        if not missing_tag_keys:
            return None

        return IAMTaggingResult(
            rule_id=rule_id,
            resource_type=resource_type,
            resource_id=resource_id,
            title=title,
            tags=user_tags,
            required_tag_keys=normalized_required_keys,
            missing_tag_keys=missing_tag_keys,
        )

    if user_tags:
        return None

    return IAMTaggingResult(
        rule_id=rule_id,
        resource_type=resource_type,
        resource_id=resource_id,
        title=title,
        tags=[],
        required_tag_keys=[],
        missing_tag_keys=[],
    )


def build_iam_tagging_finding(
    result: IAMTaggingResult,
) -> Finding:
    if result.required_tag_keys:
        description = (
            "The IAM resource is missing one or more required "
            "tag keys configured for this Security Hub control."
        )
        remediation = (
            "Add all required organizational tag keys to the "
            "IAM resource. Tag keys are case-sensitive."
        )
    else:
        description = (
            "The IAM resource has no non-system tags. "
            "AWS Security Hub evaluates this as non-compliant "
            "when no requiredTagKeys parameter is configured."
        )
        remediation = (
            "Add at least one appropriate non-system tag to the "
            "IAM resource and use consistent tagging for ownership, "
            "environment, or other inventory metadata."
        )

    return Finding(
        rule_id=result.rule_id,
        title=result.title,
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=description,
        evidence={
            "tags": result.tags,
            "non_system_tags_present": bool(result.tags),
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=remediation,
        compliance=[
            "AWS Resource Tagging Standard",
        ],
    )
