from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class NeptuneClusterResult:
    db_cluster_id: str


@dataclass(frozen=True)
class NeptuneSnapshotResult:
    snapshot_id: str


def _cluster_result(
    db_cluster_id: str,
) -> NeptuneClusterResult | None:
    if not db_cluster_id:
        return None

    return NeptuneClusterResult(
        db_cluster_id=db_cluster_id,
    )


def check_neptune_encryption(
    db_cluster_id: str,
    storage_encrypted: bool | None,
) -> NeptuneClusterResult | None:
    if not db_cluster_id or storage_encrypted is None:
        return None

    if storage_encrypted:
        return None

    return _cluster_result(db_cluster_id)


def build_neptune_encryption_finding(
    result: NeptuneClusterResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NEPTUNE-001",
        title="Neptune DB Cluster Encryption Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="neptune_db_cluster",
        resource_id=result.db_cluster_id,
        description=(
            f"The Neptune DB cluster {result.db_cluster_id} "
            "is not encrypted at rest."
        ),
        evidence={
            "db_cluster_id": result.db_cluster_id,
            "storage_encrypted": False,
        },
        remediation=(
            "Create or restore the Neptune DB cluster with "
            "encryption at rest enabled. Neptune encryption "
            "cannot be enabled on an existing unencrypted cluster."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_neptune_audit_logging(
    db_cluster_id: str,
    enabled_cloudwatch_logs_exports: list[str] | None,
) -> NeptuneClusterResult | None:
    if (
        not db_cluster_id
        or enabled_cloudwatch_logs_exports is None
    ):
        return None

    if "audit" in enabled_cloudwatch_logs_exports:
        return None

    return _cluster_result(db_cluster_id)


def build_neptune_audit_logging_finding(
    result: NeptuneClusterResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NEPTUNE-002",
        title="Neptune Audit Logs Are Not Exported to CloudWatch",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="neptune_db_cluster",
        resource_id=result.db_cluster_id,
        description=(
            f"The Neptune DB cluster {result.db_cluster_id} "
            "does not export audit logs to CloudWatch Logs."
        ),
        evidence={
            "db_cluster_id": result.db_cluster_id,
            "audit_log_export_enabled": False,
        },
        remediation=(
            "Enable the Neptune audit log export to CloudWatch Logs "
            "for the DB cluster."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
            "PCI DSS v4.0.1",
        ],
    )


def check_neptune_deletion_protection(
    db_cluster_id: str,
    deletion_protection: bool | None,
) -> NeptuneClusterResult | None:
    if not db_cluster_id or deletion_protection is None:
        return None

    if deletion_protection:
        return None

    return _cluster_result(db_cluster_id)


def build_neptune_deletion_protection_finding(
    result: NeptuneClusterResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NEPTUNE-004",
        title="Neptune Deletion Protection Is Disabled",
        severity=Severity.LOW,
        provider="aws",
        resource_type="neptune_db_cluster",
        resource_id=result.db_cluster_id,
        description=(
            f"The Neptune DB cluster {result.db_cluster_id} "
            "does not have deletion protection enabled."
        ),
        evidence={
            "db_cluster_id": result.db_cluster_id,
            "deletion_protection": False,
        },
        remediation=(
            "Enable deletion protection for the Neptune DB cluster "
            "to reduce the risk of accidental or unauthorized deletion."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_neptune_backup_retention(
    db_cluster_id: str,
    backup_retention_period: int | None,
) -> NeptuneClusterResult | None:
    if not db_cluster_id or backup_retention_period is None:
        return None

    if backup_retention_period >= 7:
        return None

    return _cluster_result(db_cluster_id)


def build_neptune_backup_retention_finding(
    result: NeptuneClusterResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NEPTUNE-005",
        title="Neptune Automated Backup Retention Is Too Short",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="neptune_db_cluster",
        resource_id=result.db_cluster_id,
        description=(
            f"The Neptune DB cluster {result.db_cluster_id} "
            "has an automated backup retention period below "
            "the Security Hub default minimum of 7 days."
        ),
        evidence={
            "db_cluster_id": result.db_cluster_id,
            "minimum_backup_retention_period": 7,
        },
        remediation=(
            "Configure the Neptune DB cluster with an automated "
            "backup retention period of at least 7 days."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
        ],
    )


def check_neptune_iam_authentication(
    db_cluster_id: str,
    iam_database_authentication_enabled: bool | None,
) -> NeptuneClusterResult | None:
    if (
        not db_cluster_id
        or iam_database_authentication_enabled is None
    ):
        return None

    if iam_database_authentication_enabled:
        return None

    return _cluster_result(db_cluster_id)


def build_neptune_iam_authentication_finding(
    result: NeptuneClusterResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NEPTUNE-007",
        title="Neptune IAM Database Authentication Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="neptune_db_cluster",
        resource_id=result.db_cluster_id,
        description=(
            f"The Neptune DB cluster {result.db_cluster_id} "
            "does not have IAM database authentication enabled."
        ),
        evidence={
            "db_cluster_id": result.db_cluster_id,
            "iam_database_authentication_enabled": False,
        },
        remediation=(
            "Enable IAM database authentication for the Neptune "
            "DB cluster where IAM-based database authentication "
            "is supported by the workload."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_neptune_multi_az(
    db_cluster_id: str,
    availability_zone_count: int | None,
) -> NeptuneClusterResult | None:
    if not db_cluster_id or availability_zone_count is None:
        return None

    if availability_zone_count >= 2:
        return None

    return _cluster_result(db_cluster_id)


def build_neptune_multi_az_finding(
    result: NeptuneClusterResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NEPTUNE-009",
        title="Neptune DB Cluster Is Not Deployed Across Multiple AZs",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="neptune_db_cluster",
        resource_id=result.db_cluster_id,
        description=(
            f"The Neptune DB cluster {result.db_cluster_id} "
            "does not have read-replica instances distributed "
            "across at least two Availability Zones."
        ),
        evidence={
            "db_cluster_id": result.db_cluster_id,
            "minimum_availability_zones": 2,
        },
        remediation=(
            "Deploy Neptune read-replica instances in at least "
            "two Availability Zones so a replica can serve as "
            "a failover target if the primary instance becomes unavailable."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )


def check_neptune_snapshot_public(
    db_cluster_snapshot_id: str,
    is_public: bool | None,
) -> NeptuneSnapshotResult | None:
    if not db_cluster_snapshot_id or is_public is None:
        return None

    if not is_public:
        return None

    return NeptuneSnapshotResult(
        snapshot_id=db_cluster_snapshot_id,
    )


def build_neptune_snapshot_public_finding(
    result: NeptuneSnapshotResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NEPTUNE-003",
        title="Neptune DB Cluster Snapshot Is Public",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="neptune_db_cluster_snapshot",
        resource_id=result.snapshot_id,
        description=(
            f"The Neptune DB cluster snapshot "
            f"{result.snapshot_id} is publicly accessible."
        ),
        evidence={
            "db_cluster_snapshot_id": result.snapshot_id,
            "public_access": True,
        },
        remediation=(
            "Remove the public restore permission from the manual "
            "Neptune DB cluster snapshot unless public sharing is "
            "explicitly required."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
            "PCI DSS v4.0.1",
        ],
    )


def check_neptune_snapshot_encryption(
    db_cluster_snapshot_id: str,
    storage_encrypted: bool | None,
) -> NeptuneSnapshotResult | None:
    if (
        not db_cluster_snapshot_id
        or storage_encrypted is None
    ):
        return None

    if storage_encrypted:
        return None

    return NeptuneSnapshotResult(
        snapshot_id=db_cluster_snapshot_id,
    )


def build_neptune_snapshot_encryption_finding(
    result: NeptuneSnapshotResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-NEPTUNE-006",
        title="Neptune DB Cluster Snapshot Is Not Encrypted",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="neptune_db_cluster_snapshot",
        resource_id=result.snapshot_id,
        description=(
            f"The Neptune DB cluster snapshot "
            f"{result.snapshot_id} is not encrypted at rest."
        ),
        evidence={
            "db_cluster_snapshot_id": result.snapshot_id,
            "storage_encrypted": False,
        },
        remediation=(
            "Create an encrypted Neptune DB cluster snapshot. "
            "An existing unencrypted snapshot cannot be encrypted "
            "in place; restore it to an encrypted cluster and create "
            "a new encrypted snapshot."
        ),
        compliance=[
            "AWS Foundational Security Best Practices",
            "NIST SP 800-53 Rev. 5",
        ],
    )
