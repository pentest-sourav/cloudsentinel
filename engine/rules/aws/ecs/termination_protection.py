from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


@dataclass(frozen=True)
class ECSTerminationProtectionResult:
    resource_arn: str
    resource_id: str
    managed_termination_protection: str | None
    resource: dict[str, Any]


def check_ecs_termination_protection(
    resource_arn: str,
    resource_id: str,
    managed_termination_protection: str | None,
    resource: dict[str, Any],
) -> ECSTerminationProtectionResult:
    return ECSTerminationProtectionResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        managed_termination_protection=(
            managed_termination_protection
        ),
        resource=resource,
    )


def build_ecs_termination_protection_finding(
    result: ECSTerminationProtectionResult,
):
    if result.managed_termination_protection == "ENABLED":
        return None

    return finding(
        rule_id="CS-AWS-ECS-019",
        title="ECS Capacity Provider Should Enable Managed Termination Protection",
        severity=Severity.MEDIUM,
        resource_type="ecs_capacity_provider",
        resource_id=result.resource_arn,
        description=(
            "The ECS capacity provider does not have managed "
            "termination protection enabled."
        ),
        evidence={
            "managed_termination_protection": (
                result.managed_termination_protection
            ),
        },
        remediation=(
            "Enable managed termination protection on the "
            "Auto Scaling group capacity provider."
        ),
        compliance="AWS Security Hub ECS.19",
    )
