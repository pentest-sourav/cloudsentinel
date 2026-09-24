from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DynamoDBPITRResult:
    table_arn: str
    table_name: str
    point_in_time_recovery_enabled: bool
    continuous_backups: dict[str, Any]


def check_dynamodb_pitr(
    table_arn: str,
    table_name: str,
    continuous_backups: dict[str, Any],
) -> DynamoDBPITRResult:
    point_in_time_recovery = continuous_backups.get(
        "PointInTimeRecoveryDescription",
        {},
    )

    if not isinstance(point_in_time_recovery, dict):
        point_in_time_recovery = {}

    enabled = (
        str(
            point_in_time_recovery.get(
                "PointInTimeRecoveryStatus"
            )
        ).upper()
        == "ENABLED"
    )

    return DynamoDBPITRResult(
        table_arn=table_arn,
        table_name=table_name,
        point_in_time_recovery_enabled=enabled,
        continuous_backups=continuous_backups,
    )


def build_dynamodb_pitr_finding(
    result: DynamoDBPITRResult,
) -> Finding | None:
    if result.point_in_time_recovery_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-DYNAMODB-002",
        title="DynamoDB Point-In-Time Recovery Is Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="dynamodb_table",
        resource_id=result.table_arn,
        description=(
            "Point-in-time recovery is not enabled for the "
            "DynamoDB table."
        ),
        evidence={
            "table_name": result.table_name,
            "point_in_time_recovery_enabled": (
                result.point_in_time_recovery_enabled
            ),
            "continuous_backups": result.continuous_backups,
        },
        remediation=(
            "Enable point-in-time recovery for the DynamoDB table."
        ),
        compliance=[
            "AWS Security Hub DynamoDB.2",
        ],
    )
