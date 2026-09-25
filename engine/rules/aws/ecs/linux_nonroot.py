from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import (
    finding,
    is_linux_or_unspecified,
)


@dataclass(frozen=True)
class ECSLinuxNonRootResult:
    resource_arn: str
    resource_id: str
    root_containers: list[str]
    resource: dict[str, Any]


def check_ecs_linux_nonroot(
    resource_arn: str,
    resource_id: str,
    container_definitions: list[dict[str, Any]],
    operating_system_family: str | None,
    resource: dict[str, Any],
) -> ECSLinuxNonRootResult:
    if (
        operating_system_family
        and not is_linux_or_unspecified(
            {
                "operating_system_family": (
                    operating_system_family
                )
            }
        )
    ):
        return ECSLinuxNonRootResult(
            resource_arn=resource_arn,
            resource_id=resource_id,
            root_containers=[],
            resource=resource,
        )

    bad: list[str] = []

    for index, container in enumerate(
        container_definitions
    ):
        user = container.get("user")

        if user is None:
            bad.append(
                str(container.get("name") or index)
            )
            continue

        if str(user).strip().lower() in {
            "root",
            "0",
            "root:root",
            "0:0",
        }:
            bad.append(
                str(container.get("name") or index)
            )

    return ECSLinuxNonRootResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        root_containers=bad,
        resource=resource,
    )


def build_ecs_linux_nonroot_finding(
    result: ECSLinuxNonRootResult,
):
    if not result.root_containers:
        return None

    return finding(
        rule_id="CS-AWS-ECS-020",
        title="ECS Linux Containers Should Run as Non-Root Users",
        severity=Severity.MEDIUM,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "One or more Linux ECS containers are configured "
            "without a non-root user."
        ),
        evidence={
            "root_containers": result.root_containers,
        },
        remediation=(
            "Configure each Linux container to run as an "
            "explicit non-root user."
        ),
        compliance="AWS Security Hub ECS.20",
    )
