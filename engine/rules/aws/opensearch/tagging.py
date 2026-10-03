from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchTaggingResult:
    domain_arn: str
    tagged: bool
    tags: list[dict[str, Any]]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]


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


def _normalize_tags(tags) -> list[dict[str, Any]]:
    if not isinstance(tags, list):
        return []

    return [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and bool(tag.get("Key"))
        and not tag["Key"].lower().startswith("aws:")
    ]


def check_opensearch_tagging(
    domain_arn: str,
    tags: list[dict[str, Any]],
    required_tag_keys=None,
) -> OpenSearchTaggingResult:
    valid_tags = _normalize_tags(tags)

    required = _normalize_required_tag_keys(
        required_tag_keys
    )

    actual_keys = {
        tag.get("Key")
        for tag in valid_tags
        if isinstance(tag.get("Key"), str)
    }

    missing = [
        key
        for key in required
        if key not in actual_keys
    ]

    if required:
        tagged = not missing
    else:
        tagged = bool(valid_tags)

    return OpenSearchTaggingResult(
        domain_arn=domain_arn,
        tagged=tagged,
        tags=valid_tags,
        required_tag_keys=required,
        missing_tag_keys=missing,
    )


def build_opensearch_tagging_finding(
    result: OpenSearchTaggingResult,
) -> Finding | None:
    if result.tagged:
        return None

    if result.required_tag_keys:
        title = (
            "OpenSearch Domain Is Missing Required Tags"
        )
        description = (
            "The OpenSearch domain is missing one or more "
            "configured required tag keys."
        )
        remediation = (
            "Add all configured required tag keys to "
            "the OpenSearch domain."
        )
    else:
        title = "OpenSearch Domain Has No Non-System Tags"
        description = (
            "The OpenSearch domain does not have any "
            "non-system tags configured."
        )
        remediation = (
            "Add appropriate ownership, environment, "
            "application, or governance tags to the "
            "OpenSearch domain."
        )

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-009",
        title=title,
        severity=Severity.LOW,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=description,
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=remediation,
        compliance=[
            "AWS Security Hub Opensearch.9",
        ],
    )
