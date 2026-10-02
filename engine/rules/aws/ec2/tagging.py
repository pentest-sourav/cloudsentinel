from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EC2TaggingResult:
    rule_id: str
    resource_type: str
    resource_id: str
    title: str
    tags: list[dict[str, Any]]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]


def _non_system_tags(
    tags: list[dict[str, Any]] | dict[str, str] | None,
) -> list[dict[str, Any]]:
    if isinstance(tags, dict):
        return [
            {
                "Key": str(key),
                "Value": value,
            }
            for key, value in tags.items()
            if not str(key).startswith("aws:")
        ]

    if not isinstance(tags, list):
        return []

    return [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and not str(tag.get("Key", "")).startswith("aws:")
    ]


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    normalized: list[str] = []

    for key in required_tag_keys:
        if not isinstance(key, str) or not key:
            continue
        if key not in normalized:
            normalized.append(key)

    return normalized


def check_ec2_tagging(
    rule_id: str,
    resource_type: str,
    resource_id: str,
    title: str,
    tags: list[dict[str, Any]] | dict[str, str] | None,
    required_tag_keys: list[str] | None = None,
) -> EC2TaggingResult | None:
    non_system_tags = _non_system_tags(tags)
    configured_keys = _normalize_required_tag_keys(
        required_tag_keys
    )

    present_keys = {
        tag.get("Key")
        for tag in non_system_tags
        if isinstance(tag.get("Key"), str)
    }

    if configured_keys:
        missing_keys = [
            key
            for key in configured_keys
            if key not in present_keys
        ]

        if not missing_keys:
            return None

        return EC2TaggingResult(
            rule_id=rule_id,
            resource_type=resource_type,
            resource_id=resource_id,
            title=title,
            tags=non_system_tags,
            required_tag_keys=configured_keys,
            missing_tag_keys=missing_keys,
        )

    if non_system_tags:
        return None

    return EC2TaggingResult(
        rule_id=rule_id,
        resource_type=resource_type,
        resource_id=resource_id,
        title=title,
        tags=[],
        required_tag_keys=[],
        missing_tag_keys=[],
    )


def build_ec2_tagging_finding(
    result: EC2TaggingResult,
) -> Finding:
    if result.required_tag_keys:
        description = (
            "The resource is missing one or more required "
            "non-system tag keys."
        )
        remediation = (
            "Add the missing required non-system tag keys: "
            + ", ".join(result.missing_tag_keys)
            + "."
        )
    else:
        description = (
            "The resource has no non-system tags. "
            "AWS Security Hub checks for the existence of "
            "a tag when no required tag-key parameter is configured."
        )
        remediation = (
            "Add at least one appropriate non-system tag to the "
            "resource for ownership, environment, or inventory "
            "management."
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
            "AWS Security Hub EC2 tagging control",
        ],
    )
