from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


@dataclass(frozen=True)
class ECSLoggingResult:
    resource_arn: str
    resource_id: str
    containers_without_logging: list[str]
    resource: dict[str, Any]


def check_ecs_logging(
    resource_arn: str,
    resource_id: str,
    container_definitions: list[dict[str, Any]],
    resource: dict[str, Any],
) -> ECSLoggingResult:
    bad: list[str] = []

    for index, container in enumerate(
        container_definitions
    ):
        config = container.get("logConfiguration")

        valid = (
            isinstance(config, dict)
            and bool(config.get("logDriver"))
        )

        if not valid:
            bad.append(
                str(container.get("name") or index)
            )

    return ECSLoggingResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        containers_without_logging=bad,
        resource=resource,
    )


def build_ecs_logging_finding(
    result: ECSLoggingResult,
):
    if not result.containers_without_logging:
        return None

    return finding(
        rule_id="CS-AWS-ECS-009",
        title="ECS Task Definitions Should Configure Logging",
        severity=Severity.HIGH,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "One or more ECS containers do not have a valid "
            "log configuration."
        ),
        evidence={
            "containers_without_logging": (
                result.containers_without_logging
            ),
        },
        remediation=(
            "Configure a supported log driver for every ECS "
            "container that requires centralized logging."
        ),
        compliance="AWS Security Hub ECS.9",
    )
