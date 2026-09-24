from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SNSTaggingResult:
    topic_arn: str
    tagged: bool
    tags: list[dict[str, Any]]


def check_sns_tagging(
    topic_arn: str,
    tags: list[dict[str, Any]],
) -> SNSTaggingResult:
    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and tag.get("Key")
    ]

    return SNSTaggingResult(
        topic_arn=topic_arn,
        tagged=bool(valid_tags),
        tags=valid_tags,
    )


def build_sns_tagging_finding(
    result: SNSTaggingResult,
) -> Finding | None:
    if result.tagged:
        return None

    return Finding(
        rule_id="CS-AWS-SNS-004",
        title="SNS Topic Has No Tags",
        severity=Severity.LOW,
        provider="aws",
        resource_type="sns_topic",
        resource_id=result.topic_arn,
        description=(
            "The SNS topic does not have any tags configured, "
            "which can reduce ownership, inventory, and governance visibility."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or other governance tags to the SNS topic."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
