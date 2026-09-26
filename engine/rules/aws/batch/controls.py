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


def _check_tags(
    *,
    resource_name: str,
    resource_arn: str,
    resource_type: str,
    control_id: str,
    tag_data_available: bool,
    has_non_system_tags: bool,
    evidence: dict | None = None,
) -> BatchResourceResult | None:
    if not resource_name or not resource_arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return BatchResourceResult(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id=control_id,
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
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
            f"any non-system tags required by "
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
            "the AWS Batch resource. CloudSentinel "
            "evaluates baseline presence of at least "
            "one non-system tag; Security Hub can "
            "additionally enforce configured "
            "requiredKeyTags."
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
) -> BatchResourceResult | None:
    return _check_tags(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Batch.1",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
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
) -> BatchResourceResult | None:
    return _check_tags(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Batch.2",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
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
) -> BatchResourceResult | None:
    return _check_tags(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Batch.3",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
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
) -> BatchResourceResult | None:
    return _check_tags(
        resource_name=resource_name,
        resource_arn=resource_arn,
        resource_type=resource_type,
        control_id="Batch.4",
        tag_data_available=tag_data_available,
        has_non_system_tags=has_non_system_tags,
        evidence={
            "compute_resource_type": compute_resource_type,
        },
    )


def build_batch_compute_resource_tags_finding(
    result: BatchResourceResult,
) -> Finding:
    return _finding(result)
