from dataclasses import dataclass, field
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SQSTaggingResult:
    queue_arn: str
    tagged: bool
    tags: list[dict[str, Any]]
    required_tag_keys: list[str] = field(default_factory=list)


def check_sqs_tagging(
    queue_arn: str,
    tags: list[dict[str, Any]],
    required_tag_keys: list[str] | None = None,
) -> SQSTaggingResult:
    required = [
        key.strip()
        for key in (required_tag_keys or [])
        if isinstance(key, str) and key.strip()
        and not key.lower().startswith("aws:")
    ]
    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and tag.get("Key")
        and not tag["Key"].startswith("aws:")
    ]

    return SQSTaggingResult(
        queue_arn=queue_arn,
        tagged=bool(valid_tags),
        tags=valid_tags,
        required_tag_keys=required,
    )


def build_sqs_tagging_finding(
    result: SQSTaggingResult,
) -> Finding | None:
    if result.required_tag_keys:
        actual = {tag.get("Key") for tag in result.tags}
        if all(key in actual for key in result.required_tag_keys):
            return None
    elif result.tagged:
        return None

    return Finding(
        rule_id="CS-AWS-SQS-002",
        title="SQS Queue Has No Tags",
        severity=Severity.LOW,
        provider="aws",
        resource_type="sqs_queue",
        resource_id=result.queue_arn,
        description=(
            "The SQS queue does not have any non-system tags "
            "configured for ownership, inventory, or governance."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or other governance tags to the SQS queue."
        ),
        compliance=[
            "AWS Security Hub SQS.2",
        ],
    )
