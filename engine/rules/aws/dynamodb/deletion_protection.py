from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DynamoDBDeletionProtectionResult:
    table_arn: str
    table_name: str
    deletion_protection_enabled: bool


def check_dynamodb_deletion_protection(
    table_arn: str,
    table_name: str,
    deletion_protection_enabled: bool,
) -> DynamoDBDeletionProtectionResult:
    return DynamoDBDeletionProtectionResult(
        table_arn=table_arn,
        table_name=table_name,
        deletion_protection_enabled=(
            deletion_protection_enabled is True
        ),
    )


def build_dynamodb_deletion_protection_finding(
    result: DynamoDBDeletionProtectionResult,
) -> Finding | None:
    if result.deletion_protection_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-DYNAMODB-006",
        title="DynamoDB Table Does Not Have Deletion Protection Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="dynamodb_table",
        resource_id=result.table_arn,
        description=(
            "Deletion protection is not enabled for the "
            "DynamoDB table."
        ),
        evidence={
            "table_name": result.table_name,
            "deletion_protection_enabled": (
                result.deletion_protection_enabled
            ),
        },
        remediation=(
            "Enable deletion protection for the DynamoDB table "
            "to reduce the risk of accidental deletion."
        ),
        compliance=[
            "AWS Security Hub DynamoDB.6",
        ],
    )
