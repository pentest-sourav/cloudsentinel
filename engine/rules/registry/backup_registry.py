from engine.findings.model import Finding, Severity
from engine.rules.aws.backup.protection import (
    check_backup_plan_frequency_retention,
    check_backup_plan_selection,
    check_backup_recovery_point_encryption,
    check_backup_vault_lock,
)
from engine.rules.model import RuleDefinition
from engine.rules.registry.base import RuleRegistry


BACKUP_RULES = RuleRegistry(
    [
        RuleDefinition(
            rule_id="CS-AWS-BACKUP-001",
            name=(
                "aws_backup_recovery_point_encryption"
            ),
            data_source="backup_recovery_points",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "encryption_key_arn",
                "encryption_key_type",
                "status",
            ],
            check=(
                check_backup_recovery_point_encryption
            ),
            build_finding=(
                lambda result: _build_encryption_finding(
                    result
                )
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-BACKUP-002",
            name=(
                "aws_backup_plan_resource_selection"
            ),
            data_source="backup_plans",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "plan_name",
                "selection_count",
                "rules_count",
                "selections",
            ],
            check=check_backup_plan_selection,
            build_finding=(
                lambda result: _build_selection_finding(
                    result
                )
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-BACKUP-003",
            name=(
                "aws_backup_plan_frequency_retention"
            ),
            data_source="backup_plans",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "plan_name",
                "rules",
            ],
            check=check_backup_plan_frequency_retention,
            build_finding=(
                lambda result: _build_lifecycle_finding(
                    result
                )
            ),
        ),
        RuleDefinition(
            rule_id="CS-AWS-BACKUP-004",
            name=(
                "aws_backup_vault_lock"
            ),
            data_source="backup_vaults",
            collection_mode="multiple",
            check_arguments=[
                "resource_id",
                "locked",
                "lock_date",
                "min_retention_days",
                "max_retention_days",
                "vault_state",
            ],
            check=check_backup_vault_lock,
            build_finding=(
                lambda result: _build_vault_lock_finding(
                    result
                )
            ),
        ),
    ]
)


def _build_encryption_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-BACKUP-001",
        title=(
            "AWS Backup Recovery Point Is Not "
            "Reported As Encrypted"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="backup_recovery_point",
        resource_id=result.resource_id,
        description=(
            "The AWS Backup recovery point does not "
            "report an encryption key. Backup recovery "
            "points should be protected by encryption "
            "at rest."
        ),
        evidence={
            "resource_id": result.resource_id,
            "encryption_key_arn": (
                result.encryption_key_arn
            ),
            "encryption_key_type": (
                result.encryption_key_type
            ),
            "status": result.status,
            "encrypted_at_rest": False,
        },
        remediation=(
            "Use an encrypted AWS Backup vault and "
            "ensure recovery points are created in "
            "that encrypted vault."
        ),
        compliance=[
            "AWS Security Hub Backup.1",
        ],
    )


def _build_selection_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-BACKUP-002",
        title=(
            "AWS Backup Plan Has No Resource Selection"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="backup_plan",
        resource_id=result.resource_id,
        description=(
            f"The AWS Backup plan "
            f"{result.plan_name or result.resource_id} "
            "contains no backup selections. A backup "
            "plan without a selection does not identify "
            "resources for protection."
        ),
        evidence={
            "plan_id": result.resource_id,
            "plan_name": result.plan_name,
            "selection_count": (
                result.selection_count
            ),
            "rules_count": result.rules_count,
            "selections": result.selections,
        },
        remediation=(
            "Create and associate at least one "
            "appropriate AWS Backup selection with "
            "the backup plan."
        ),
        compliance=[
            "AWS Backup Audit Manager: "
            "Backup resources are included in at least "
            "one backup plan",
        ],
    )


def _build_lifecycle_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-BACKUP-003",
        title=(
            "AWS Backup Plan Does Not Meet "
            "Minimum Frequency And Retention"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="backup_plan",
        resource_id=result.resource_id,
        description=(
            f"The AWS Backup plan "
            f"{result.plan_name or result.resource_id} "
            "does not contain a rule that satisfies "
            "both the configured minimum backup "
            "frequency and minimum retention period."
        ),
        evidence={
            "plan_id": result.resource_id,
            "plan_name": result.plan_name,
            "has_valid_frequency": (
                result.has_valid_frequency
            ),
            "has_valid_retention": (
                result.has_valid_retention
            ),
            "minimum_frequency_hours": (
                result.minimum_frequency_hours
            ),
            "minimum_retention_days": (
                result.minimum_retention_days
            ),
            "rules": result.rules,
        },
        remediation=(
            "Configure at least one backup rule with "
            "a backup frequency of no more than one day "
            "and a retention period of at least 35 days, "
            "or adjust these thresholds to match your "
            "organization's documented backup policy."
        ),
        compliance=[
            "AWS Backup Audit Manager: "
            "Backup plan has minimum frequency "
            "and minimum retention",
        ],
    )


def _build_vault_lock_finding(
    result,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-BACKUP-004",
        title=(
            "AWS Backup Vault Does Not Have "
            "Vault Lock Protection"
        ),
        severity=Severity.HIGH,
        provider="aws",
        resource_type="backup_vault",
        resource_id=result.resource_id,
        description=(
            f"The AWS Backup vault "
            f"{result.resource_id} is not configured "
            "with Vault Lock. Without Vault Lock, "
            "authorized identities with sufficient "
            "permissions may be able to manually delete "
            "recovery points."
        ),
        evidence={
            "vault_name": result.resource_id,
            "locked": result.locked,
            "lock_date": result.lock_date,
            "min_retention_days": (
                result.min_retention_days
            ),
            "max_retention_days": (
                result.max_retention_days
            ),
            "vault_state": result.vault_state,
        },
        remediation=(
            "Configure AWS Backup Vault Lock for "
            "vaults that require protection against "
            "manual deletion of recovery points. "
            "Use an appropriate retention window for "
            "the workload's recovery requirements."
        ),
        compliance=[
            "AWS Backup Audit Manager: "
            "Vaults prevent manual deletion of "
            "recovery points",
        ],
    )
