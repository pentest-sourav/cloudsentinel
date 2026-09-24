from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class StepFunctionsTaggingResult:
    activity_arn: str
    tagged: bool
    tags: list[dict[str, Any]]


def check_stepfunctions_tagging(
    activity_arn: str,
    tags: list[dict[str, Any]],
) -> StepFunctionsTaggingResult:
    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("key"), str)
        and tag.get("key")
        and not tag["key"].startswith("aws:")
    ]

    return StepFunctionsTaggingResult(
        activity_arn=activity_arn,
        tagged=bool(valid_tags),
        tags=valid_tags,
    )


def build_stepfunctions_tagging_finding(
    result: StepFunctionsTaggingResult,
) -> Finding | None:
    if result.tagged:
        return None

    return Finding(
        rule_id="CS-AWS-SFN-002",
        title="Step Functions Activity Has No Tags",
        severity=Severity.LOW,
        provider="aws",
        resource_type="stepfunctions_activity",
        resource_id=result.activity_arn,
        description=(
            "The Step Functions activity does not have any "
            "non-system tags configured for ownership, inventory, "
            "or governance."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or other governance tags to the Step Functions activity."
        ),
        compliance=[
            "AWS Security Hub StepFunctions.2",
        ],
    )
