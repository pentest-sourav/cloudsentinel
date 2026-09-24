from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DynamoDBTaggingResult:
    table_arn: str
    tagged: bool
    tags: list[dict[str, Any]]


def check_dynamodb_tagging(
    table_arn: str,
    tags: list[dict[str, Any]],
) -> DynamoDBTaggingResult:
    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and tag.get("Key")
        and not tag["Key"].startswith("aws:")
    ]

    return DynamoDBTaggingResult(
        table_arn=table_arn,
        tagged=bool(valid_tags),
        tags=valid_tags,
    )


def build_dynamodb_tagging_finding(
    result: DynamoDBTaggingResult,
) -> Finding | None:
    if result.tagged:
        return None

    return Finding(
        rule_id="CS-AWS-DYNAMODB-005",
        title="DynamoDB Table Has No Tags",
        severity=Severity.LOW,
        provider="aws",
        resource_type="dynamodb_table",
        resource_id=result.table_arn,
        description=(
            "The DynamoDB table does not have any non-system tags "
            "configured for ownership, inventory, or governance."
        ),
        evidence={
            "tagged": result.tagged,
            "tags": result.tags,
        },
        remediation=(
            "Add appropriate ownership, environment, application, "
            "or other governance tags to the DynamoDB table."
        ),
        compliance=[
            "AWS Security Hub DynamoDB.5",
        ],
    )
