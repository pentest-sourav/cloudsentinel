from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import (
    finding,
    non_system_tags,
)


@dataclass(frozen=True)
class ECSServiceTaggingResult:
    resource_arn: str
    resource_id: str
    tags: list[dict[str, Any]]
    tagged: bool
    resource: dict[str, Any]


def check_ecs_service_tagging(
    resource_arn: str,
    resource_id: str,
    tags: list[dict[str, Any]],
    resource: dict[str, Any],
) -> ECSServiceTaggingResult:
    valid_tags = non_system_tags(tags)

    return ECSServiceTaggingResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        tags=valid_tags,
        tagged=bool(valid_tags),
        resource=resource,
    )


def build_ecs_service_tagging_finding(
    result: ECSServiceTaggingResult,
):
    if result.tagged:
        return None

    return finding(
        rule_id="CS-AWS-ECS-013",
        title="ECS Service Should Be Tagged",
        severity=Severity.LOW,
        resource_type="ecs_service",
        resource_id=result.resource_arn,
        description=(
            "The ECS service does not have any non-system tags."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or governance tags to the ECS service."
        ),
        compliance="AWS Security Hub ECS.13",
    )
