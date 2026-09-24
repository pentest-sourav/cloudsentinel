from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DynamoDBBackupPlanResult:
    table_arn: str
    table_name: str
    table_status: str | None
    protected_by_backup_plan: bool
    protected_resource: dict[str, Any] | None


def check_dynamodb_backup_plan(
    table_arn: str,
    table_name: str,
    table_status: str | None,
    backup_resources: list[dict[str, Any]],
) -> DynamoDBBackupPlanResult:
    protected_resource = None

    for resource in backup_resources:
        resource_arn = resource.get("ResourceArn")

        if resource_arn == table_arn:
            protected_resource = resource
            break

    protected = (
        table_status == "ACTIVE"
        and protected_resource is not None
    )

    return DynamoDBBackupPlanResult(
        table_arn=table_arn,
        table_name=table_name,
        table_status=table_status,
        protected_by_backup_plan=protected,
        protected_resource=protected_resource,
    )


def build_dynamodb_backup_plan_finding(
    result: DynamoDBBackupPlanResult,
) -> Finding | None:
    if result.protected_by_backup_plan:
        return None

    return Finding(
        rule_id="CS-AWS-DYNAMODB-004",
        title="DynamoDB Table Is Not Present In A Backup Plan",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="dynamodb_table",
        resource_id=result.table_arn,
        description=(
            "The active DynamoDB table is not identified as a "
            "resource protected by an AWS Backup backup plan."
        ),
        evidence={
            "table_name": result.table_name,
            "table_status": result.table_status,
            "protected_by_backup_plan": (
                result.protected_by_backup_plan
            ),
            "protected_resource": result.protected_resource,
        },
        remediation=(
            "Assign the DynamoDB table to an AWS Backup backup plan "
            "with the required backup schedule and retention."
        ),
        compliance=[
            "AWS Security Hub DynamoDB.4",
        ],
    )
