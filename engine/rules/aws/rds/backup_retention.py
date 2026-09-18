from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSBackupRetentionResult:
    db_instance_id: str
    backup_retention_period: int


def check_rds_backup_retention(
    db_instance_id: str,
    backup_retention_period: int,
) -> RDSBackupRetentionResult | None:
    if not db_instance_id:
        return None

    if backup_retention_period > 0:
        return None

    return RDSBackupRetentionResult(
        db_instance_id=db_instance_id,
        backup_retention_period=backup_retention_period,
    )


def build_rds_backup_retention_finding(
    result: RDSBackupRetentionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RDS-003",
        title="RDS Backup Retention Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS instance {result.db_instance_id} "
            "has no automated backup retention configured. "
            "Without automated backups, recovery options may be "
            "limited if data is accidentally deleted or corrupted."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "backup_retention_period": result.backup_retention_period,
            "sensitive_data": True,
        },
        remediation=(
            "Configure an appropriate automated backup retention period "
            "for the RDS instance according to the application's "
            "recovery and data-retention requirements."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
