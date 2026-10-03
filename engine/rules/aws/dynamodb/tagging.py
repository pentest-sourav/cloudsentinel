from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DynamoDBTaggingResult:
    table_arn: str
    tags: list[dict[str, Any]]
    required_tag_keys: list[str]
    missing_tag_keys: list[str]

    @property
    def tagged(self) -> bool:
        if self.required_tag_keys:
            return not self.missing_tag_keys

        return any(
            isinstance(tag, dict)
            and isinstance(tag.get("Key"), str)
            and bool(tag.get("Key"))
            and not tag["Key"].lower().startswith("aws:")
            for tag in self.tags
        )


def _normalize_required_tag_keys(
    required_tag_keys: list[str] | None,
) -> list[str]:
    if not isinstance(required_tag_keys, list):
        return []

    result = []

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue
        key = key.strip()
        if not key or key.lower().startswith("aws:"):
            continue
        if key not in result:
            result.append(key)

    return result


def check_dynamodb_tagging(
    table_arn: str,
    tags: list[dict[str, Any]],
    required_tag_keys: list[str] | None = None,
) -> DynamoDBTaggingResult:
    required = _normalize_required_tag_keys(required_tag_keys)

    valid_tags = [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and bool(tag.get("Key"))
        and not tag["Key"].lower().startswith("aws:")
    ]

    present = {
        tag["Key"]
        for tag in valid_tags
    }

    missing = [
        key
        for key in required
        if key not in present
    ]

    return DynamoDBTaggingResult(
        table_arn=table_arn,
        tags=valid_tags,
        required_tag_keys=required,
        missing_tag_keys=missing,
    )


def build_dynamodb_tagging_finding(
    result: DynamoDBTaggingResult,
) -> Finding | None:
    if result.required_tag_keys:
        if not result.missing_tag_keys:
            return None
    else:
        if any(
            isinstance(tag, dict)
            and isinstance(tag.get("Key"), str)
            and tag.get("Key")
            and not tag["Key"].lower().startswith("aws:")
            for tag in result.tags
        ):
            return None

    return Finding(
        rule_id="CS-AWS-DYNAMODB-005",
        title="DynamoDB Table Has No Required Tags",
        severity=Severity.LOW,
        provider="aws",
        resource_type="dynamodb_table",
        resource_id=result.table_arn,
        description=(
            "The DynamoDB table does not satisfy the configured "
            "tagging requirements."
        ),
        evidence={
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
            "missing_tag_keys": result.missing_tag_keys,
        },
        remediation=(
            "Add the missing required tag keys using "
            "case-sensitive matching."
            if result.required_tag_keys
            else
            "Add at least one appropriate non-system tag."
        ),
        compliance=["AWS Security Hub DynamoDB.5"],
    )
