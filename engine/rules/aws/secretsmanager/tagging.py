from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity

from engine.rules.aws.secretsmanager.common import (
    has_non_system_tags,
)


@dataclass(frozen=True)
class SecretsManagerTaggingResult:
    resource_id: str
    resource_arn: str
    tags: list[dict[str, Any]]
    required_tag_keys: list[str]


def check_secretsmanager_tagging(
    resource_id: str,
    resource_arn: str,
    tags: list[dict[str, Any]],
    required_tag_keys: list[str] | None = None,
) -> SecretsManagerTaggingResult | None:
    required = [
        key.strip()
        for key in (required_tag_keys or [])
        if isinstance(key, str) and key.strip()
        and not key.lower().startswith("aws:")
    ]
    actual = {
        tag.get("Key")
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("Key"), str)
        and tag.get("Key")
        and not tag["Key"].lower().startswith("aws:")
    }
    missing = [key for key in dict.fromkeys(required) if key not in actual]
    if required and not missing:
        return None
    if not required and has_non_system_tags(tags):
        return None
    return SecretsManagerTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        tags=tags,
        required_tag_keys=required,
    )


def build_secretsmanager_tagging_finding(
    result: SecretsManagerTaggingResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SECRETSMANAGER-005",
        title="Secrets Manager Secret Is Not Tagged",
        severity=Severity.LOW,
        provider="aws",
        resource_type="secretsmanager_secret",
        resource_id=result.resource_id,
        description=(
            "The Secrets Manager secret does not have "
            "a non-system tag."
        ),
        evidence={
            "secret_arn": result.resource_arn,
            "tags": result.tags,
            "required_tag_keys": result.required_tag_keys,
        },
        remediation=(
            "Add at least one meaningful non-system tag "
            "to the Secrets Manager secret."
        ),
        compliance=[
            "AWS Security Hub SecretsManager.5",
        ],
    )
