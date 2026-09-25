from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


@dataclass(frozen=True)
class ECSPIDNamespaceResult:
    resource_arn: str
    resource_id: str
    pid_mode: str | None
    resource: dict[str, Any]


def check_ecs_pid_namespace(
    resource_arn: str,
    resource_id: str,
    pid_mode: str | None,
    resource: dict[str, Any],
) -> ECSPIDNamespaceResult:
    return ECSPIDNamespaceResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        pid_mode=pid_mode,
        resource=resource,
    )


def build_ecs_pid_namespace_finding(
    result: ECSPIDNamespaceResult,
):
    if result.pid_mode != "host":
        return None

    return finding(
        rule_id="CS-AWS-ECS-003",
        title="ECS Task Definition Should Not Share Host PID Namespace",
        severity=Severity.HIGH,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "The ECS task definition uses the host PID namespace."
        ),
        evidence={
            "pid_mode": result.pid_mode,
        },
        remediation=(
            "Remove host PID namespace sharing from the ECS "
            "task definition."
        ),
        compliance="AWS Security Hub ECS.3",
    )
