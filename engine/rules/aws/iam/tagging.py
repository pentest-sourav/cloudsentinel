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
            if not key.startswith("aws:")
        ]

    return [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and not str(tag.get("Key", "")).startswith("aws:")
    ]


def check_iam_tagging(
    rule_id: str,
    resource_type: str,
    resource_id: str,
    title: str,
    tags: list[dict[str, Any]] | dict[str, str],
) -> IAMTaggingResult | None:
    user_tags = _non_system_tags(tags)

    if user_tags:
        return None

    return IAMTaggingResult(
        rule_id=rule_id,
        resource_type=resource_type,
        resource_id=resource_id,
        title=title,
        tags=[],
    )


def build_iam_tagging_finding(
    result: IAMTaggingResult,
) -> Finding:
    return Finding(
        rule_id=result.rule_id,
        title=result.title,
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            "The IAM resource has no non-system tags. "
            "AWS Security Hub evaluates this as non-compliant "
            "when no requiredTagKeys parameter is configured."
        ),
        evidence={
            "tags": result.tags,
            "non_system_tags_present": False,
        },
        remediation=(
            "Add at least one appropriate non-system tag to the "
            "IAM resource and use consistent tagging for ownership, "
            "environment, or other inventory metadata."
        ),
        compliance=[
            "AWS Resource Tagging Standard",
        ],
    )
