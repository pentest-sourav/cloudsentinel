from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import (
    finding,
    non_system_tags,
)


@dataclass(frozen=True)
class ECSTaskDefinitionTaggingResult:
    resource_arn: str
    resource_id: str
    tags: list[dict[str, Any]]
    tagged: bool
    resource: dict[str, Any]


def check_ecs_task_definition_tagging(
    resource_arn: str,
    resource_id: str,
    tags: list[dict[str, Any]],
    resource: dict[str, Any],
) -> ECSTaskDefinitionTaggingResult:
    valid_tags = non_system_tags(tags)

    return ECSTaskDefinitionTaggingResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        tags=valid_tags,
        tagged=bool(valid_tags),
        resource=resource,
    )


def build_ecs_task_definition_tagging_finding(
    result: ECSTaskDefinitionTaggingResult,
):
    if result.tagged:
        return None

    return finding(
        rule_id="CS-AWS-ECS-015",
        title="ECS Task Definition Should Be Tagged",
        severity=Severity.LOW,
        resource_type="ecs_task_definition",
        resource_id=result.resource_arn,
        description=(
            "The ECS task definition does not have any "
            "non-system tags."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or governance tags to the ECS task definition."
        ),
        compliance="AWS Security Hub ECS.15",
    )
