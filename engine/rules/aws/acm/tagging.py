from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity

from engine.rules.aws.acm.common import (
    has_non_system_tags,
)


@dataclass(frozen=True)
class ACMTaggingResult:
    resource_id: str
    resource_arn: str
    tags: list[dict[str, Any]]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    normalized: list[str] = []
    seen: set[str] = set()

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue

        key = key.strip()
        if not key or key.lower().startswith("aws:"):
            continue

        if key not in seen:
            seen.add(key)
            normalized.append(key)

    return normalized


def _missing_required_tag_keys(
    tags: list[dict[str, Any]],
    required_tag_keys: list[str],
) -> list[str]:
    if not required_tag_keys:
        return []

    present_keys = {
        tag.get("Key")
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and not tag["Key"].lower().startswith("aws:")
    }

    return [
        key
        for key in required_tag_keys
        if key not in present_keys
    ]


def check_acm_tagging(
    resource_id: str,
    resource_arn: str,
    tags: list[dict[str, Any]],
    required_tag_keys: list[str] | None = None,
) -> ACMTaggingResult | None:
    normalized_required = _normalize_required_tag_keys(
        required_tag_keys
    )

    missing = _missing_required_tag_keys(
        tags,
        normalized_required,
    )

    if normalized_required:
        if not missing:
            return None
    elif has_non_system_tags(tags):
        return None

    return ACMTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        tags=tags,
        required_tag_keys=normalized_required,
        missing_tag_keys=missing,
    )


def build_acm_tagging_finding(
    result: ACMTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-ACM-003",
        title="ACM Certificate Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="acm_certificate",
        resource_id=result.resource_id,
        description=(
            "The ACM certificate does not have "
            "a non-system tag."
        ),
        evidence={
            "certificate_arn": result.resource_arn,
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=(
            (
                "Add the missing required tag keys to the ACM "
                "certificate: "
                + ", ".join(result.missing_tag_keys)
            )
            if result.required_tag_keys
            else (
                "Add at least one meaningful non-system "
                "tag to the ACM certificate."
            )
        ),
        compliance=[
            "AWS Security Hub ACM.3",
        ],
    )
