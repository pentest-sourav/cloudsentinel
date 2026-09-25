from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


@dataclass(frozen=True)
class ECSNetworkModeResult:
    resource_arn: str
    resource_id: str
    network_mode: str | None
    resource: dict[str, Any]


def check_ecs_network_mode(
    resource_arn: str,
    resource_id: str,
    network_mode: str | None,
    resource: dict[str, Any],
) -> ECSNetworkModeResult:
    return ECSNetworkModeResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        network_mode=network_mode,
        resource=resource,
    )


def build_ecs_network_mode_finding(
    result: ECSNetworkModeResult,
):
    if result.network_mode != "host":
        return None

    return finding(
        rule_id="CS-AWS-ECS-017",
        title="ECS Task Definition Should Not Use Host Network Mode",
        severity=Severity.MEDIUM,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "The ECS task definition uses host network mode."
        ),
        evidence={
            "network_mode": result.network_mode,
        },
        remediation=(
            "Use a non-host ECS network mode appropriate for "
            "the workload."
        ),
        compliance="AWS Security Hub ECS.17",
    )
