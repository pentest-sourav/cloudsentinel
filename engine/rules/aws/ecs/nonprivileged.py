from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import (
    containers,
    finding,
)


@dataclass(frozen=True)
class ECSNonPrivilegedResult:
    resource_arn: str
    resource_id: str
    privileged_containers: list[str]
    resource: dict[str, Any]


def check_ecs_nonprivileged(
    resource_arn: str,
    resource_id: str,
    container_definitions: list[dict[str, Any]],
    resource: dict[str, Any],
) -> ECSNonPrivilegedResult:
    privileged = [
        str(container.get("name") or index)
        for index, container in enumerate(
            container_definitions
        )
        if container.get("privileged") is True
    ]

    return ECSNonPrivilegedResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        privileged_containers=privileged,
        resource=resource,
    )


def build_ecs_nonprivileged_finding(
    result: ECSNonPrivilegedResult,
):
    if not result.privileged_containers:
        return None

    return finding(
        rule_id="CS-AWS-ECS-004",
        title="ECS Containers Should Run Without Privileged Mode",
        severity=Severity.HIGH,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "One or more ECS containers are configured with "
            "privileged mode enabled."
        ),
        evidence={
            "privileged_containers": (
                result.privileged_containers
            ),
        },
        remediation=(
            "Disable privileged mode unless it is explicitly "
            "required and governed."
        ),
        compliance="AWS Security Hub ECS.4",
    )
