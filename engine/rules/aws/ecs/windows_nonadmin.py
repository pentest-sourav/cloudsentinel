from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


@dataclass(frozen=True)
class ECSWindowsNonAdminResult:
    resource_arn: str
    resource_id: str
    administrator_containers: list[str]
    resource: dict[str, Any]


def check_ecs_windows_nonadmin(
    resource_arn: str,
    resource_id: str,
    container_definitions: list[dict[str, Any]],
    operating_system_family: str | None,
    resource: dict[str, Any],
) -> ECSWindowsNonAdminResult:
    if not (
        isinstance(operating_system_family, str)
        and operating_system_family.upper().startswith(
            "WINDOWS"
        )
    ):
        return ECSWindowsNonAdminResult(
            resource_arn=resource_arn,
            resource_id=resource_id,
            administrator_containers=[],
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

        if (
            str(user).strip().lower()
            == "containeradministrator"
        ):
            bad.append(
                str(container.get("name") or index)
            )

    return ECSWindowsNonAdminResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        administrator_containers=bad,
        resource=resource,
    )


def build_ecs_windows_nonadmin_finding(
    result: ECSWindowsNonAdminResult,
):
    if not result.administrator_containers:
        return None

    return finding(
        rule_id="CS-AWS-ECS-021",
        title="ECS Windows Containers Should Not Run as Administrator",
        severity=Severity.MEDIUM,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "One or more Windows ECS containers are configured "
            "without a non-administrator user."
        ),
        evidence={
            "administrator_containers": (
                result.administrator_containers
            ),
        },
        remediation=(
            "Configure each Windows container to run as a "
            "non-administrator user."
        ),
        compliance="AWS Security Hub ECS.21",
    )
