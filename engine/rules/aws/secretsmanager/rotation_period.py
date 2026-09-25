from dataclasses import dataclass
from datetime import datetime

from engine.findings.model import Finding, Severity

from engine.rules.aws.secretsmanager.common import (
    DEFAULT_MAX_ROTATION_DAYS,
    format_datetime,
    is_older_than_days,
)


@dataclass(frozen=True)
class SecretsManagerRotationPeriodResult:
    resource_id: str
    resource_arn: str
    last_rotated_date: datetime | None
    max_days_since_rotation: int


def check_secretsmanager_rotation_period(
    resource_id: str,
    resource_arn: str,
    last_rotated_date: datetime | None,
    max_days_since_rotation: int = (
        DEFAULT_MAX_ROTATION_DAYS
    ),
) -> SecretsManagerRotationPeriodResult | None:
    if not is_older_than_days(
        last_rotated_date,
        max_days_since_rotation,
    ):
        return None

    return SecretsManagerRotationPeriodResult(
        resource_id=resource_id,
        resource_arn=resource_arn,
        last_rotated_date=last_rotated_date,
        max_days_since_rotation=max_days_since_rotation,
    )


def build_secretsmanager_rotation_period_finding(
    result: SecretsManagerRotationPeriodResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SECRETSMANAGER-004",
        title=(
            "Secrets Manager Secret Has Not Been "
            "Rotated Within the Required Period"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="secretsmanager_secret",
        resource_id=result.resource_id,
        description=(
            "The Secrets Manager secret has not been "
            "rotated within the configured maximum "
            "rotation interval."
        ),
        evidence={
            "secret_arn": result.resource_arn,
            "last_rotated_date": format_datetime(
                result.last_rotated_date
            ),
            "max_days_since_rotation": (
                result.max_days_since_rotation
            ),
        },
        remediation=(
            "Rotate the secret and configure a rotation "
            "schedule that keeps the secret within the "
            "required rotation interval."
        ),
        compliance=[
            "AWS Security Hub SecretsManager.4",
        ],
    )
