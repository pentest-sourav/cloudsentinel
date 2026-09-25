from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import (
    finding,
    non_system_tags,
)


@dataclass(frozen=True)
class ECSClusterTaggingResult:
    resource_arn: str
    resource_id: str
    tags: list[dict[str, Any]]
    tagged: bool
    resource: dict[str, Any]


def check_ecs_cluster_tagging(
    resource_arn: str,
    resource_id: str,
    tags: list[dict[str, Any]],
    resource: dict[str, Any],
) -> ECSClusterTaggingResult:
    valid_tags = non_system_tags(tags)

    return ECSClusterTaggingResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        tags=valid_tags,
        tagged=bool(valid_tags),
        resource=resource,
    )


def build_ecs_cluster_tagging_finding(
    result: ECSClusterTaggingResult,
):
    if result.tagged:
        return None

    return finding(
        rule_id="CS-AWS-ECS-014",
        title="ECS Cluster Should Be Tagged",
        severity=Severity.LOW,
        resource_type="ecs_cluster",
        resource_id=result.resource_arn,
        description=(
            "The ECS cluster does not have any non-system tags."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or governance tags to the ECS cluster."
        ),
        compliance="AWS Security Hub ECS.14",
    )
