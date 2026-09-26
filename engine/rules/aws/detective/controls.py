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


def _result(
    *,
    name: str,
    arn: str,
    resource_type: str,
    control_id: str,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> DetectiveResult:
    return DetectiveResult(
        resource_name=name,
        resource_arn=arn,
        resource_type=resource_type,
        control_id=control_id,
        reason=reason,
        evidence=evidence or {},
    )


def _finding(
    result: DetectiveResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-DETECTIVE-001",
        title="Detective Behavior Graph Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_arn,
        description=(
            f"Amazon Detective behavior graph "
            f"{result.resource_name} does not have "
            "any non-system tags."
        ),
        evidence={
            "resource_name": result.resource_name,
            "resource_arn": result.resource_arn,
            "security_hub_control": result.control_id,
            "configuration_issue": result.reason,
            **result.evidence,
        },
        remediation=(
            "Add the required organizational tags to "
            "the Detective behavior graph."
        ),
        compliance=[
            f"AWS Security Hub {result.control_id}",
        ],
    )


def check_detective_graph_tags(
    resource_name,
    resource_arn,
    resource_type,
    tag_data_available,
    has_non_system_tags,
):
    if not resource_name or not resource_arn:
        return None

    if not tag_data_available:
        return None

    if has_non_system_tags:
        return None

    return _result(
        name=resource_name,
        arn=resource_arn,
        resource_type=resource_type,
        control_id="Detective.1",
        reason="missing_non_system_tags",
        evidence={
            "has_non_system_tags": False,
        },
    )


def build_detective_graph_tags_finding(
    result,
):
    return _finding(result)
