from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class BackupTaggingResult:
    resource_id: str
    resource_arn: str
    resource_type: str
    control_id: str
    tags: list[dict[str, str]]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    result: list[str] = []

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
    tags: list[dict[str, str]] | None,
    required_tag_keys: list[str],
) -> list[str]:
    present = {
        tag.get("Key")
        for tag in tags or []
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and not tag["Key"].lower().startswith("aws:")
    }

    return [
        key
        for key in required_tag_keys
        if key not in present
    ]


def check_backup_tagging(
    resource_id: str,
    resource_arn: str,
    resource_type: str,
    control_id: str,
    tags: list[dict[str, str]],
    required_tag_keys: list[str] | None = None,
) -> BackupTaggingResult | None:
    required = _normalize_required_tag_keys(required_tag_keys)
    missing = _missing_required_tag_keys(tags, required)

    if required:
        if not missing:
            return None
    else:
        non_system = [
            tag
            for tag in tags
            if isinstance(tag, dict)
            and isinstance(tag.get("Key"), str)
            and tag.get("Key")
            and not tag["Key"].lower().startswith("aws:")
        ]

        if non_system:
            return None

    return BackupTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id=control_id,
        tags=tags,
        required_tag_keys=required,
        missing_tag_keys=missing,
    )


def build_backup_tagging_finding(
    result: BackupTaggingResult,
) -> Finding:
    return Finding(
        rule_id=result.control_id,
        title="AWS Backup Resource Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_arn,
        description=(
            "The AWS Backup resource does not satisfy the "
            "configured resource-tagging requirements."
        ),
        evidence={
            "resource_id": result.resource_id,
            "resource_arn": result.resource_arn,
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=(
            "Add all configured required tag keys to the AWS Backup "
            "resource using case-sensitive key matching."
            if result.required_tag_keys
            else
            "Add at least one appropriate non-system tag to the "
            "AWS Backup resource."
        ),
        compliance=[
            f"AWS Security Hub {result.control_id}",
        ],
    )
