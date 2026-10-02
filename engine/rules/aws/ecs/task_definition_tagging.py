from dataclasses import dataclass
from typing import Any

from engine.findings.model import Severity
from engine.rules.aws.ecs.common import (
    finding,
    has_required_tag_keys,
    normalize_required_tag_keys,
)


@dataclass(frozen=True)
class ECSTaskDefinitionTaggingResult:
    resource_arn: str
    resource_id: str
    tags: list[dict[str, Any]]
    tagged: bool
    required_tag_keys: tuple[str, ...]
    resource: dict[str, Any]


def check_ecs_task_definition_tagging(
    resource_arn: str,
    resource_id: str,
    tags: list[dict[str, Any]],
    resource: dict[str, Any],
    required_tag_keys: list[str] | tuple[str, ...] | None = None,
) -> ECSTaskDefinitionTaggingResult:
    normalized_required_tag_keys = normalize_required_tag_keys(
        required_tag_keys,
    )

    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(
            tag.get("key", tag.get("Key")),
            str,
        )
        and tag.get("key", tag.get("Key"))
        and not str(
            tag.get("key", tag.get("Key"))
        ).lower().startswith("aws:")
    ]

    tagged = has_required_tag_keys(
        tags,
        normalized_required_tag_keys,
    )

    return ECSTaskDefinitionTaggingResult(
        resource_arn=resource_arn,
        resource_id=resource_id,
        tags=valid_tags,
        tagged=tagged,
        required_tag_keys=normalized_required_tag_keys,
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
            "The ECS task definition does not satisfy the "
            "configured required tagging policy."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
            "required_tag_keys": list(
                result.required_tag_keys
            ),
        },
        remediation=(
            "Add the required non-system tag keys to "
            "the ECS task definition."
        ),
        compliance="AWS Security Hub ECS.15",
    )
