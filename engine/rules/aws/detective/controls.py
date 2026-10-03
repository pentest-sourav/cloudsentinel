from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DetectiveResult:
    resource_name: str
    resource_arn: str
    resource_type: str
    control_id: str
    reason: str
    evidence: dict[str, Any]


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    result = []

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue
        key = key.strip()
        if not key or key.lower().startswith("aws:"):
            continue
        if key not in result:
            result.append(key)

    return result


def _missing_required_tag_keys(
    tags: dict[str, str] | None,
    required_tag_keys: list[str],
) -> list[str]:
    present = {
        key
        for key in (tags or {})
        if isinstance(key, str)
        and not key.lower().startswith("aws:")
    }

    return [
        key
        for key in required_tag_keys
        if key not in present
    ]


def check_detective_graph_tags(
    resource_name,
    resource_arn,
    resource_type,
    tag_data_available,
    has_non_system_tags,
    tags=None,
    required_tag_keys=None,
):
    if not resource_name or not resource_arn:
        return None

    if not tag_data_available:
        return None

    required = _normalize_required_tag_keys(required_tag_keys)
    missing = _missing_required_tag_keys(tags, required)

    if required:
        if not missing:
            return None
    elif has_non_system_tags:
        return None

    return DetectiveResult(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Detective.1",
        reason=(
            "missing_required_tag_keys"
            if required
            else "missing_non_system_tags"
        ),
        evidence={
            "has_non_system_tags": has_non_system_tags,
            "tags": tags or {},
            "required_tag_keys": required,
            "missing_tag_keys": missing,
        },
    )


def build_detective_graph_tags_finding(
    result,
):
    return Finding(
        rule_id="CS-AWS-DETECTIVE-001",
        title="Detective Behavior Graph Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_arn,
        description=(
            f"Amazon Detective behavior graph {result.resource_name} "
            "does not satisfy the configured tagging requirements."
        ),
        evidence={
            "resource_name": result.resource_name,
            "resource_arn": result.resource_arn,
            "security_hub_control": result.control_id,
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=(
            "Add all configured required tag keys using "
            "case-sensitive matching."
            if result.evidence["required_tag_keys"]
            else
            "Add at least one appropriate non-system tag."
        ),
        compliance=[
            f"AWS Security Hub {result.control_id}",
        ],
    )
