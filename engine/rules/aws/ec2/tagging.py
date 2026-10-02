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


def check_ec2_tagging(
    rule_id: str,
    resource_type: str,
    resource_id: str,
    title: str,
    tags: list[dict[str, Any]] | dict[str, str] | None,
) -> EC2TaggingResult | None:
    if _non_system_tags(tags):
        return None

    return EC2TaggingResult(
        rule_id=rule_id,
        resource_type=resource_type,
        resource_id=resource_id,
        title=title,
        tags=[],
    )


def build_ec2_tagging_finding(
    result: EC2TaggingResult,
) -> Finding:
    return Finding(
        rule_id=result.rule_id,
        title=result.title,
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=(
            "The resource has no non-system tags. "
            "AWS Security Hub evaluates this resource as "
            "non-compliant when no requiredTagKeys parameter "
            "is configured."
        ),
        evidence={
            "tags": result.tags,
            "non_system_tags_present": False,
        },
        remediation=(
            "Add at least one appropriate non-system tag to the "
            "resource for ownership, environment, or inventory "
            "management."
        ),
        compliance=[
            "AWS Security Hub EC2 tagging control",
        ],
    )
