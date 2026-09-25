from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


@dataclass(frozen=True)
class ECSPublicIPResult:
    resource_arn: str
    resource_id: str
    assign_public_ip: str | None
    resource: dict[str, Any]


def check_ecs_public_ip(
    resource_arn: str,
    resource_id: str,
    network_configuration: dict[str, Any],
    resource: dict[str, Any],
) -> ECSPublicIPResult:
    awsvpc = network_configuration.get(
        "awsvpcConfiguration",
        {},
    )

    if not isinstance(awsvpc, dict):
        awsvpc = {}

    value = awsvpc.get("assignPublicIp")

    return ECSPublicIPResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        assign_public_ip=value
        if isinstance(value, str)
        else None,
        resource=resource,
    )


def build_ecs_public_ip_finding(
    result: ECSPublicIPResult,
):
    if result.assign_public_ip != "ENABLED":
        return None

    return finding(
        rule_id="CS-AWS-ECS-002",
        title="ECS Service Should Not Automatically Assign Public IPs",
        severity=Severity.HIGH,
        resource_type="ecs_service",
        resource_id=result.resource_arn,
        description=(
            "The ECS service is configured to automatically "
            "assign public IP addresses."
        ),
        evidence={
            "assign_public_ip": result.assign_public_ip,
        },
        remediation=(
            "Disable automatic public IP assignment on the "
            "ECS service network configuration."
        ),
        compliance="AWS Security Hub ECS.2",
    )
