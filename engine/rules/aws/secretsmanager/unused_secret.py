from dataclasses import dataclass
from datetime import datetime

from engine.findings.model import Finding, Severity

from engine.rules.aws.secretsmanager.common import (
    DEFAULT_UNUSED_DAYS,
    format_datetime,
    is_older_than_days,
)


@dataclass(frozen=True)
class SecretsManagerUnusedSecretResult:
    resource_id: str
    resource_arn: str
    last_accessed_date: datetime | None
    unused_for_days: int


def check_secretsmanager_unused_secret(
    resource_id: str,
    resource_arn: str,
    last_accessed_date: datetime | None,
    unused_for_days: int = DEFAULT_UNUSED_DAYS,
) -> SecretsManagerUnusedSecretResult | None:
    if not is_older_than_days(
        last_accessed_date,
        unused_for_days,
    ):
        return None

    return SecretsManagerUnusedSecretResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        last_accessed_date=last_accessed_date,
        unused_for_days=unused_for_days,
    )


def build_secretsmanager_unused_secret_finding(
    result: SecretsManagerUnusedSecretResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SECRETSMANAGER-003",
        title="Secrets Manager Secret Is Unused",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="secretsmanager_secret",
        resource_id=result.resource_id,
        description=(
            "The Secrets Manager secret has not been "
            "accessed within the configured unused-secret "
            "window."
        ),
        evidence={
            "secret_arn": result.resource_arn,
            "last_accessed_date": format_datetime(
                result.last_accessed_date
            ),
            "unused_for_days": result.unused_for_days,
        },
        remediation=(
            "Remove the unused secret if it is no longer "
            "required, or verify and document why it must "
            "remain available."
        ),
        compliance=[
            "AWS Security Hub SecretsManager.3",
        ],
    )
