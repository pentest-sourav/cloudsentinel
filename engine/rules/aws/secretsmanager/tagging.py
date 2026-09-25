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


def check_secretsmanager_tagging(
    resource_id: str,
    resource_arn: str,
    tags: list[dict[str, Any]],
) -> SecretsManagerTaggingResult | None:
    if has_non_system_tags(tags):
        return None

    return SecretsManagerTaggingResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        tags=tags,
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
        },
        remediation=(
            "Add at least one meaningful non-system tag "
            "to the Secrets Manager secret."
        ),
        compliance=[
            "AWS Security Hub SecretsManager.5",
        ],
    )
