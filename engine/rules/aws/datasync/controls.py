from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DataSyncResult:
    resource_name: str
    resource_arn: str
    resource_type: str
    control_id: str
    reason: str
    evidence: dict[str, Any]


def _result(
    *,
    name: str,
    arn: str,
    resource_type: str,
    control_id: str,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> DataSyncResult:
    return DataSyncResult(
        resource_name=name,
        resource_arn=arn,
        resource_type=resource_type,
        control_id=control_id,
        reason=reason,
        evidence=evidence or {},
    )


def _finding(
    result: DataSyncResult,
    severity: Severity,
    title: str,
    description: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=(
            "CS-AWS-DATASYNC-"
            f"{result.control_id.split('.')[-1].zfill(3)}"
        ),
        title=title,
        severity=severity,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_arn,
        description=description,
        evidence={
            "resource_name": result.resource_name,
            "resource_arn": result.resource_arn,
            "security_hub_control": result.control_id,
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=remediation,
        compliance=[
            f"AWS Security Hub {result.control_id}",
        ],
    )


# ============================================================
# DATASYNC.1 — TASK LOGGING
# ============================================================

def check_datasync_task_logging(
    resource_name,
    resource_arn,
    resource_type,
    task_mode,
    log_level,
    cloudwatch_log_group_arn,
):
    if not resource_name or not resource_arn:
        return None

    mode = str(task_mode or "").upper()
    level = str(log_level or "").upper()

    if mode == "ENHANCED":
        if level in {"OFF", "NONE"}:
            return _result(
                name=resource_name,
                arn=resource_arn,
                resource_type=resource_type,
                control_id="DataSync.1",
                reason="task_logging_disabled",
                evidence={
                    "task_mode": task_mode,
                    "log_level": log_level,
                    "cloudwatch_log_group_arn": (
                        cloudwatch_log_group_arn
                    ),
                },
            )

        return None

    if level in {"OFF", "NONE", ""}:
        return _result(
            name=resource_name,
            arn=resource_arn,
            resource_type=resource_type,
            control_id="DataSync.1",
            reason="task_logging_disabled",
            evidence={
                "task_mode": task_mode,
                "log_level": log_level,
                "cloudwatch_log_group_arn": (
                    cloudwatch_log_group_arn
                ),
            },
        )

    if not isinstance(
        cloudwatch_log_group_arn,
        str,
    ) or not cloudwatch_log_group_arn:
        return _result(
            name=resource_name,
            arn=resource_arn,
            resource_type=resource_type,
            control_id="DataSync.1",
            reason="cloudwatch_log_group_not_configured",
            evidence={
                "task_mode": task_mode,
                "log_level": log_level,
                "cloudwatch_log_group_arn": (
                    cloudwatch_log_group_arn
                ),
            },
        )

    return None


def build_datasync_task_logging_finding(
    result,
):
    return _finding(
        result,
        Severity.MEDIUM,
        "DataSync Task Logging Is Not Enabled",
        (
            f"AWS DataSync task "
            f"{result.resource_name} does not have "
            "the required task logging configuration."
        ),
        (
            "Enable DataSync task logging and configure "
            "CloudWatch Logs for the task. Enhanced mode "
            "tasks use the /aws/datasync log group automatically."
        ),
    )


# ============================================================
# DATASYNC.2 — TASK TAGGING
# ============================================================

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


def _missing_required_tag_keys(
    tags: dict[str, str],
    required_tag_keys: list[str],
) -> list[str]:
    actual_keys = {
        key
        for key in tags
        if isinstance(key, str)
        and not key.lower().startswith("aws:")
    }

    return [
        key
        for key in required_tag_keys
        if key not in actual_keys
    ]


def check_datasync_task_tags(
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

    normalized_tags = (
        tags
        if isinstance(tags, dict)
        else {}
    )

    required = _normalize_required_tag_keys(
        required_tag_keys
    )

    if required:
        missing = _missing_required_tag_keys(
            normalized_tags,
            required,
        )

        if not missing:
            return None

        return _result(
            name=resource_name,
            arn=resource_arn,
            resource_type=resource_type,
            control_id="DataSync.2",
            reason="missing_required_tag_keys",
            evidence={
                "tags": normalized_tags,
                "required_tag_keys": required,
                "missing_tag_keys": missing,
            },
        )

    if has_non_system_tags:
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="DataSync.2",
        reason="missing_non_system_tags",
        evidence={
            "tags": normalized_tags,
            "has_non_system_tags": False,
            "required_tag_keys": [],
            "missing_tag_keys": [],
        },
    )


def build_datasync_task_tags_finding(
    result,
):
    if result.reason == "missing_required_tag_keys":
        description = (
            f"AWS DataSync task "
            f"{result.resource_name} is missing one or "
            "more required tag keys."
        )
        remediation = (
            "Add all configured required tag keys to "
            "the DataSync task."
        )
    else:
        description = (
            f"AWS DataSync task "
            f"{result.resource_name} does not have "
            "any non-system tags."
        )
        remediation = (
            "Add the required organizational tags to "
            "the DataSync task."
        )

    return _finding(
        result,
        Severity.LOW,
        "DataSync Task Is Not Properly Tagged",
        description,
        remediation,
    )
