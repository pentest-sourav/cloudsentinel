from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import finding


SECRET_KEYS = {
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "ECS_ENGINE_AUTH_DATA",
}


@dataclass(frozen=True)
class ECSEnvironmentSecretsResult:
    resource_arn: str
    resource_id: str
    secret_keys: list[str]
    resource: dict[str, Any]


def check_ecs_environment_secrets(
    resource_arn: str,
    resource_id: str,
    container_definitions: list[dict[str, Any]],
    resource: dict[str, Any],
) -> ECSEnvironmentSecretsResult:
    found: list[str] = []

    for container in container_definitions:
        environment = container.get(
            "environment",
            [],
        )

        if not isinstance(environment, list):
            continue

        for variable in environment:
            if not isinstance(variable, dict):
                continue

            name = variable.get("name")

            if name in SECRET_KEYS:
                found.append(name)

    return ECSEnvironmentSecretsResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        secret_keys=sorted(set(found)),
        resource=resource,
    )


def build_ecs_environment_secrets_finding(
    result: ECSEnvironmentSecretsResult,
):
    if not result.secret_keys:
        return None

    return finding(
        rule_id="CS-AWS-ECS-008",
        title="ECS Task Definitions Should Not Pass Secrets as Environment Variables",
        severity=Severity.HIGH,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "The task definition contains sensitive AWS "
            "credential environment variable names."
        ),
        evidence={
            "secret_keys": result.secret_keys,
        },
        remediation=(
            "Store sensitive values in AWS Secrets Manager or "
            "SSM Parameter Store and reference them through "
            "the ECS secrets configuration."
        ),
        compliance="AWS Security Hub ECS.8",
    )
