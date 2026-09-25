from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


@dataclass(frozen=True)
class ECSTaskSetPublicIPResult:
    resource_arn: str
    resource_id: str
    assign_public_ip: str | None
    resource: dict[str, Any]


def check_ecs_task_set_public_ip(
    resource_arn: str,
    resource_id: str,
    network_configuration: dict[str, Any],
    resource: dict[str, Any],
) -> ECSTaskSetPublicIPResult:
    awsvpc = network_configuration.get(
        "awsvpcConfiguration",
        {},
    )

    if not isinstance(awsvpc, dict):
        awsvpc = {}

    value = awsvpc.get("assignPublicIp")

    return ECSTaskSetPublicIPResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        assign_public_ip=value
        if isinstance(value, str)
        else None,
        resource=resource,
    )


def build_ecs_task_set_public_ip_finding(
    result: ECSTaskSetPublicIPResult,
):
    if result.assign_public_ip != "ENABLED":
        return None

    return finding(
        rule_id="CS-AWS-ECS-016",
        title="ECS Task Set Should Not Automatically Assign Public IPs",
        severity=Severity.HIGH,
        resource_type="ecs_task_set",
        resource_id=result.resource_arn,
        description=(
            "The ECS task set is configured to automatically "
            "assign public IP addresses."
        ),
        evidence={
            "assign_public_ip": result.assign_public_ip,
        },
        remediation=(
            "Disable automatic public IP assignment for the "
            "ECS task set."
        ),
        compliance="AWS Security Hub ECS.16",
    )
