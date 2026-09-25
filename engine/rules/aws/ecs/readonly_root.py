from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import (
    containers,
    finding,
    is_windows,
)


@dataclass(frozen=True)
class ECSReadonlyRootResult:
    resource_arn: str
    resource_id: str
    non_readonly_containers: list[str]
    resource: dict[str, Any]


def check_ecs_readonly_root(
    resource_arn: str,
    resource_id: str,
    container_definitions: list[dict[str, Any]],
    operating_system_family: str | None,
    resource: dict[str, Any],
) -> ECSReadonlyRootResult:
    if (
        isinstance(operating_system_family, str)
        and operating_system_family.upper().startswith(
            "WINDOWS"
        )
    ):
        return ECSReadonlyRootResult(
            resource_arn=resource_arn,
            resource_id=resource_id,
            non_readonly_containers=[],
            resource=resource,
        )

    bad = [
        str(container.get("name") or index)
        for index, container in enumerate(
            container_definitions
        )
        if container.get("readonlyRootFilesystem") is not True
    ]

    return ECSReadonlyRootResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        non_readonly_containers=bad,
        resource=resource,
    )


def build_ecs_readonly_root_finding(
    result: ECSReadonlyRootResult,
):
    if not result.non_readonly_containers:
        return None

    return finding(
        rule_id="CS-AWS-ECS-005",
        title="ECS Containers Should Use Read-Only Root Filesystems",
        severity=Severity.HIGH,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "One or more evaluated ECS containers do not have "
            "a read-only root filesystem."
        ),
        evidence={
            "non_readonly_containers": (
                result.non_readonly_containers
            ),
        },
        remediation=(
            "Set readonlyRootFilesystem to true for each "
            "Linux container."
        ),
        compliance="AWS Security Hub ECS.5",
    )
