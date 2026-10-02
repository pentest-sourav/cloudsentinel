from __future__ import annotations

from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class BatchResourceResult:
    resource_name: str
    resource_arn: str
    resource_type: str
    control_id: str
    reason: str
    evidence: dict


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
    tags: dict[str, str] | None,
    required_tag_keys: list[str],
) -> list[str]:
    if not required_tag_keys:
        return []

    present_keys = {
        key
        for key in (tags or {})
        if isinstance(key, str)
        and not key.lower().startswith("aws:")
    }

    return [
        key
        for key in required_tag_keys
        if key not in present_keys
    ]


def _check_tags(
    *,
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    control_id: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
    tags: dict[str, str] | None = None,
    required_tag_keys: list[str] | None = None,
    evidence: dict | None = None,
) -> BatchResourceResult | None:
    if not resource_name or not resource_arn:
        return None

    if not tag_data_available:
        return None

    normalized_required = _normalize_required_tag_keys(
        required_tag_keys
    )

    missing_required = _missing_required_tag_keys(
        tags,
        normalized_required,
    )

    if normalized_required:
        if not missing_required:
            return None
    elif has_non_system_tags:
        return None

    return BatchResourceResult(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id=control_id,
        reason=(
            "missing_required_tag_keys"
            if normalized_required
            else "missing_non_system_tags"
        ),
        evidence={
            "has_non_system_tags": has_non_system_tags,
            "required_tag_keys": normalized_required,
            "missing_tag_keys": missing_required,
            **(evidence or {}),
        },
    )


def _finding(
    result: BatchResourceResult,
) -> Finding:
    control_number = result.control_id.split(".")[-1]

    return Finding(
        rule_id=(
            f"CS-AWS-BATCH-{control_number.zfill(3)}"
        ),
        title=(
            f"AWS Batch {result.control_id} "
            "resource is not tagged"
        ),
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_arn,
        description=(
            f"AWS Batch resource "
            f"{result.resource_name} does not have "
            f"the required tags for "
            f"Security Hub {result.control_id}."
        ),
        evidence={
            "resource_name": result.resource_name,
            "resource_arn": result.resource_arn,
            "configuration_issue": result.reason,
            "security_hub_control": result.control_id,
            **result.evidence,
        },
        remediation=(
            "Add the required organizational tags to "
            "the AWS Batch resource. When requiredTagKeys "
            "is configured, all configured keys must be "
            "present using case-sensitive matching."
        ),
        compliance=[
            f"AWS Security Hub {result.control_id}",
        ],
    )


def check_batch_job_queue_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
    tags: dict[str, str] | None = None,
    required_tag_keys: list[str] | None = None,
) -> BatchResourceResult | None:
    return _check_tags(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Batch.1",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
        tags=tags,
        required_tag_keys=required_tag_keys,
    )


def build_batch_job_queue_tags_finding(
    result: BatchResourceResult,
) -> Finding:
    return _finding(result)


def check_batch_scheduling_policy_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
    tags: dict[str, str] | None = None,
    required_tag_keys: list[str] | None = None,
) -> BatchResourceResult | None:
    return _check_tags(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Batch.2",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
        tags=tags,
        required_tag_keys=required_tag_keys,
    )


def build_batch_scheduling_policy_tags_finding(
    result: BatchResourceResult,
) -> Finding:
    return _finding(result)


def check_batch_compute_environment_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
    tags: dict[str, str] | None = None,
    required_tag_keys: list[str] | None = None,
) -> BatchResourceResult | None:
    return _check_tags(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Batch.3",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
        tags=tags,
        required_tag_keys=required_tag_keys,
    )


def build_batch_compute_environment_tags_finding(
    result: BatchResourceResult,
) -> Finding:
    return _finding(result)


def check_batch_compute_resource_tags(
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
    compute_resource_type: str | None = None,
    tags: dict[str, str] | None = None,
    required_tag_keys: list[str] | None = None,
) -> BatchResourceResult | None:
    return _check_tags(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Batch.4",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
        tags=tags,
        required_tag_keys=required_tag_keys,
        evidence={
            "compute_resource_type": compute_resource_type,
        },
    )


def build_batch_compute_resource_tags_finding(
    result: BatchResourceResult,
) -> Finding:
    return _finding(result)
