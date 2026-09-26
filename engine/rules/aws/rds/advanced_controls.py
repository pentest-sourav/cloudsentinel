from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSControlResult:
    resource_id: str
    resource_type: str
    control: str
    evidence: dict[str, Any]


def _result(
    resource_id: str,
    resource_type: str,
    control: str,
    evidence: dict[str, Any],
) -> RDSControlResult:
    return RDSControlResult(
        resource_id=resource_id,
        resource_type=resource_type,
        control=control,
        evidence=evidence,
    )


def _finding(
    result: RDSControlResult,
    rule_id: str,
    title: str,
    severity: Severity,
    description: str,
    remediation: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        provider="aws",
        resource_type=result.resource_type,
        resource_id=result.resource_id,
        description=description,
        evidence=result.evidence,
        remediation=remediation,
        compliance=["AWS Security Hub CSPM"],
    )


# ---------------------------------------------------------------------
# Snapshot controls
# ---------------------------------------------------------------------


def check_rds_snapshot_private(
    snapshot_id: str,
    shared_accounts: list[str] | None,
) -> RDSControlResult | None:
    if not snapshot_id or shared_accounts is None:
        return None

    if not shared_accounts:
        return None

    return _result(
        snapshot_id,
        "rds_snapshot",
        "snapshot_private",
        {
            "snapshot_id": snapshot_id,
            "shared_accounts": list(shared_accounts),
            "public_access": "*" in shared_accounts,
        },
    )


def build_rds_snapshot_private_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-010",
        "RDS Snapshot Is Publicly Shared",
        Severity.CRITICAL,
        (
            f"RDS snapshot {result.resource_id} has restore permissions "
            "granted to external AWS accounts or public access."
        ),
        (
            "Remove unnecessary snapshot sharing permissions and keep "
            "RDS snapshots private."
        ),
    )


def check_rds_snapshot_encryption(
    snapshot_id: str,
    encrypted: bool | None,
) -> RDSControlResult | None:
    if not snapshot_id or encrypted is None or encrypted:
        return None

    return _result(
        snapshot_id,
        "rds_snapshot",
        "snapshot_encryption",
        {
            "snapshot_id": snapshot_id,
            "encrypted": False,
        },
    )


def build_rds_snapshot_encryption_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-011",
        "RDS Snapshot Encryption Is Disabled",
        Severity.MEDIUM,
        f"RDS snapshot {result.resource_id} is not encrypted at rest.",
        (
            "Create encrypted snapshots using an appropriate KMS key and "
            "avoid retaining unencrypted database snapshots."
        ),
    )


def check_rds_cluster_snapshot_private(
    snapshot_id: str,
    shared_accounts: list[str] | None,
) -> RDSControlResult | None:
    if not snapshot_id or shared_accounts is None:
        return None

    if not shared_accounts:
        return None

    return _result(
        snapshot_id,
        "rds_cluster_snapshot",
        "cluster_snapshot_private",
        {
            "snapshot_id": snapshot_id,
            "shared_accounts": list(shared_accounts),
            "public_access": "*" in shared_accounts,
        },
    )


def build_rds_cluster_snapshot_private_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-012",
        "RDS Cluster Snapshot Is Publicly Shared",
        Severity.CRITICAL,
        (
            f"RDS cluster snapshot {result.resource_id} has restore "
            "permissions granted to external AWS accounts or public access."
        ),
        (
            "Remove unnecessary cluster snapshot sharing permissions "
            "and keep snapshots private."
        ),
    )


def check_rds_cluster_snapshot_encryption(
    snapshot_id: str,
    encrypted: bool | None,
) -> RDSControlResult | None:
    if not snapshot_id or encrypted is None or encrypted:
        return None

    return _result(
        snapshot_id,
        "rds_cluster_snapshot",
        "cluster_snapshot_encryption",
        {
            "snapshot_id": snapshot_id,
            "encrypted": False,
        },
    )


def build_rds_cluster_snapshot_encryption_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-013",
        "RDS Cluster Snapshot Encryption Is Disabled",
        Severity.MEDIUM,
        f"RDS cluster snapshot {result.resource_id} is not encrypted at rest.",
        (
            "Create encrypted cluster snapshots using an appropriate "
            "KMS key."
        ),
    )


# ---------------------------------------------------------------------
# Cluster controls
# ---------------------------------------------------------------------


def check_rds_cluster_deletion_protection(
    cluster_id: str,
    deletion_protection: bool | None,
) -> RDSControlResult | None:
    if not cluster_id or deletion_protection is None:
        return None

    if deletion_protection:
        return None

    return _result(
        cluster_id,
        "rds_cluster",
        "cluster_deletion_protection",
        {
            "db_cluster_id": cluster_id,
            "deletion_protection": False,
        },
    )


def build_rds_cluster_deletion_protection_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-014",
        "RDS Cluster Deletion Protection Is Disabled",
        Severity.MEDIUM,
        f"RDS cluster {result.resource_id} does not have deletion protection enabled.",
        "Enable deletion protection for production RDS clusters.",
    )


def check_rds_cluster_encryption(
    cluster_id: str,
    encrypted: bool | None,
) -> RDSControlResult | None:
    if not cluster_id or encrypted is None or encrypted:
        return None

    return _result(
        cluster_id,
        "rds_cluster",
        "cluster_encryption",
        {
            "db_cluster_id": cluster_id,
            "storage_encrypted": False,
        },
    )


def build_rds_cluster_encryption_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-015",
        "RDS Cluster Encryption Is Disabled",
        Severity.MEDIUM,
        f"RDS cluster {result.resource_id} is not encrypted at rest.",
        "Enable encryption at rest using an appropriate AWS KMS key.",
    )


def check_rds_cluster_iam_auth(
    cluster_id: str,
    engine: str | None,
    enabled: bool | None,
) -> RDSControlResult | None:
    supported = {
        "aurora",
        "aurora-mysql",
        "aurora-postgresql",
        "mysql",
        "postgres",
        "mariadb",
    }

    if not cluster_id or not engine or enabled is None:
        return None

    if engine.lower() not in supported:
        return None

    if enabled:
        return None

    return _result(
        cluster_id,
        "rds_cluster",
        "cluster_iam_authentication",
        {
            "db_cluster_id": cluster_id,
            "engine": engine,
            "iam_database_authentication_enabled": False,
        },
    )


def build_rds_cluster_iam_auth_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-016",
        "RDS Cluster IAM Authentication Is Disabled",
        Severity.MEDIUM,
        f"RDS cluster {result.resource_id} does not have IAM authentication enabled.",
        (
            "Enable IAM database authentication where supported and "
            "appropriate for the workload."
        ),
    )


def check_rds_cluster_backup_retention(
    cluster_id: str,
    retention: int | None,
) -> RDSControlResult | None:
    if not cluster_id or retention is None:
        return None

    if retention >= 7:
        return None

    return _result(
        cluster_id,
        "rds_cluster",
        "cluster_backup_retention",
        {
            "db_cluster_id": cluster_id,
            "backup_retention_period": retention,
            "minimum_required_days": 7,
        },
    )


def build_rds_cluster_backup_retention_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-017",
        "RDS Cluster Backup Retention Is Too Short",
        Severity.MEDIUM,
        (
            f"RDS cluster {result.resource_id} has less than the default "
            "7-day backup retention requirement."
        ),
        (
            "Configure at least 7 days of automated backup retention "
            "or the organization's approved minimum."
        ),
    )


def check_rds_cluster_minor_upgrade(
    cluster_id: str,
    engine: str | None,
    enabled: bool | None,
) -> RDSControlResult | None:
    if not cluster_id or not engine or enabled is None:
        return None

    if not engine.lower().startswith("aurora"):
        return None

    if enabled:
        return None

    return _result(
        cluster_id,
        "rds_cluster",
        "cluster_minor_upgrade",
        {
            "db_cluster_id": cluster_id,
            "engine": engine,
            "auto_minor_version_upgrade": False,
        },
    )


def build_rds_cluster_minor_upgrade_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-018",
        "Aurora Cluster Automatic Minor Version Upgrade Is Disabled",
        Severity.HIGH,
        (
            f"Aurora cluster {result.resource_id} does not have automatic "
            "minor version upgrades enabled."
        ),
        (
            "Enable automatic minor version upgrades at the Aurora "
            "cluster level and ensure compatible instances are configured."
        ),
    )


# ---------------------------------------------------------------------
# Instance controls
# ---------------------------------------------------------------------


def check_rds_default_port(
    db_instance_id: str,
    engine: str | None,
    port: int | None,
) -> RDSControlResult | None:
    defaults = {
        "mysql": 3306,
        "mariadb": 3306,
        "postgres": 5432,
        "oracle-ee": 1521,
        "oracle-se2": 1521,
        "oracle-se1": 1521,
        "oracle-se": 1521,
        "sqlserver-ee": 1433,
        "sqlserver-se": 1433,
        "sqlserver-ex": 1433,
        "sqlserver-web": 1433,
        "aurora": 3306,
        "aurora-mysql": 3306,
        "aurora-postgresql": 5432,
    }

    if not db_instance_id or not engine or port is None:
        return None

    default_port = defaults.get(engine.lower())

    if default_port is None or port != default_port:
        return None

    return _result(
        db_instance_id,
        "rds_instance",
        "non_default_port",
        {
            "db_instance_id": db_instance_id,
            "engine": engine,
            "port": port,
            "default_port": default_port,
        },
    )


def build_rds_default_port_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-019",
        "RDS Instance Uses the Database Engine Default Port",
        Severity.LOW,
        (
            f"RDS instance {result.resource_id} uses the default port "
            f"{result.evidence['default_port']} for its database engine."
        ),
        (
            "Consider configuring a non-default database port and "
            "restricting network access through security groups."
        ),
    )


def _default_admin_usernames(engine: str) -> set[str]:
    values = {
        "postgres": {"postgres"},
        "mysql": {"admin"},
        "mariadb": {"admin"},
        "aurora": {"admin"},
        "aurora-mysql": {"admin"},
        "aurora-postgresql": {"postgres"},
        "oracle-ee": {"admin"},
        "oracle-se2": {"admin"},
        "oracle-se1": {"admin"},
        "oracle-se": {"admin"},
        "sqlserver-ee": {"admin"},
        "sqlserver-se": {"admin"},
        "sqlserver-ex": {"admin"},
        "sqlserver-web": {"admin"},
    }
    return values.get(engine.lower(), set())


def check_rds_instance_admin_username(
    db_instance_id: str,
    engine: str | None,
    admin_username: str | None,
    db_cluster_identifier: str | None,
) -> RDSControlResult | None:
    if (
        not db_instance_id
        or not engine
        or not admin_username
        or db_cluster_identifier
    ):
        return None

    defaults = _default_admin_usernames(engine)

    if admin_username.lower() not in defaults:
        return None

    return _result(
        db_instance_id,
        "rds_instance",
        "custom_admin_username",
        {
            "db_instance_id": db_instance_id,
            "engine": engine,
            "admin_username": admin_username,
        },
    )


def build_rds_instance_admin_username_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-020",
        "RDS Instance Uses a Default Administrator Username",
        Severity.MEDIUM,
        (
            f"RDS instance {result.resource_id} appears to use a "
            "known default administrator username."
        ),
        (
            "Use a custom administrator username when creating the "
            "database instance."
        ),
    )


def check_rds_cluster_admin_username(
    cluster_id: str,
    engine: str | None,
    admin_username: str | None,
) -> RDSControlResult | None:
    if not cluster_id or not engine or not admin_username:
        return None

    defaults = _default_admin_usernames(engine)

    if admin_username.lower() not in defaults:
        return None

    return _result(
        cluster_id,
        "rds_cluster",
        "custom_admin_username",
        {
            "db_cluster_id": cluster_id,
            "engine": engine,
            "master_username": admin_username,
        },
    )


def build_rds_cluster_admin_username_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-021",
        "RDS Cluster Uses a Default Administrator Username",
        Severity.MEDIUM,
        (
            f"RDS cluster {result.resource_id} appears to use a "
            "known default administrator username."
        ),
        "Use a custom administrator username when creating the cluster.",
    )


# ---------------------------------------------------------------------
# Tagging
# ---------------------------------------------------------------------


def _missing_tags(
    resource_id: str,
    resource_type: str,
    tags: list[dict[str, str]] | None,
) -> RDSControlResult | None:
    if not resource_id or tags is None:
        return None

    if tags:
        return None

    return _result(
        resource_id,
        resource_type,
        "tagged",
        {
            "resource_id": resource_id,
            "tag_count": 0,
            "tags": [],
        },
    )


def build_rds_tag_finding(
    result: RDSControlResult,
    rule_id: str,
    title: str,
) -> Finding:
    return _finding(
        result,
        rule_id,
        title,
        Severity.LOW,
        f"RDS resource {result.resource_id} has no tags.",
        (
            "Apply the organization's required resource tags for "
            "ownership, environment, cost allocation, and governance."
        ),
    )


def check_rds_cluster_tagged(
    cluster_id: str,
    tags: list[dict[str, str]] | None,
) -> RDSControlResult | None:
    return _missing_tags(cluster_id, "rds_cluster", tags)


def check_rds_cluster_snapshot_tagged(
    snapshot_id: str,
    tags: list[dict[str, str]] | None,
) -> RDSControlResult | None:
    return _missing_tags(snapshot_id, "rds_cluster_snapshot", tags)


def check_rds_instance_tagged(
    db_instance_id: str,
    tags: list[dict[str, str]] | None,
) -> RDSControlResult | None:
    return _missing_tags(db_instance_id, "rds_instance", tags)


def check_rds_snapshot_tagged(
    snapshot_id: str,
    tags: list[dict[str, str]] | None,
) -> RDSControlResult | None:
    return _missing_tags(snapshot_id, "rds_snapshot", tags)


def check_rds_subnet_group_tagged(
    subnet_group_name: str,
    tags: list[dict[str, str]] | None,
) -> RDSControlResult | None:
    return _missing_tags(subnet_group_name, "rds_subnet_group", tags)


def check_rds_security_group_tagged(
    security_group_name: str,
    tags: list[dict[str, str]] | None,
) -> RDSControlResult | None:
    return _missing_tags(
        security_group_name,
        "rds_security_group",
        tags,
    )


# ---------------------------------------------------------------------
# Aurora logging / tag-copy controls
# ---------------------------------------------------------------------


def check_aurora_mysql_audit_logs(
    cluster_id: str,
    engine: str | None,
    logs: list[str] | None,
) -> RDSControlResult | None:
    if not cluster_id or not engine or logs is None:
        return None

    if engine.lower() not in {"aurora", "aurora-mysql"}:
        return None

    normalized = {
        str(value).strip().lower()
        for value in logs
        if str(value).strip()
    }

    if "audit" in normalized:
        return None

    return _result(
        cluster_id,
        "rds_cluster",
        "aurora_mysql_audit_logs",
        {
            "db_cluster_id": cluster_id,
            "engine": engine,
            "enabled_cloudwatch_logs_exports": sorted(normalized),
        },
    )


def build_aurora_mysql_audit_logs_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-022",
        "Aurora MySQL Audit Logs Are Not Exported",
        Severity.MEDIUM,
        (
            f"Aurora MySQL cluster {result.resource_id} does not "
            "export audit logs to CloudWatch Logs."
        ),
        (
            "Enable the Aurora MySQL audit log export to CloudWatch "
            "Logs where required by the security monitoring policy."
        ),
    )


def check_rds_cluster_copy_tags(
    cluster_id: str,
    engine: str | None,
    copy_tags_to_snapshot: bool | None,
) -> RDSControlResult | None:
    if (
        not cluster_id
        or not engine
        or copy_tags_to_snapshot is None
    ):
        return None

    normalized = engine.lower()

    if normalized not in {
        "mysql",
        "aurora",
        "aurora-mysql",
        "postgres",
        "aurora-postgresql",
    }:
        return None

    if copy_tags_to_snapshot:
        return None

    return _result(
        cluster_id,
        "rds_cluster",
        "copy_tags_to_snapshot",
        {
            "db_cluster_id": cluster_id,
            "engine": engine,
            "copy_tags_to_snapshot": False,
        },
    )


def build_rds_cluster_copy_tags_finding(
    result: RDSControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-RDS-023",
        "RDS Cluster Does Not Copy Tags to Snapshots",
        Severity.LOW,
        (
            f"RDS cluster {result.resource_id} does not have "
            "CopyTagsToSnapshot enabled."
        ),
        (
            "Enable CopyTagsToSnapshot for supported RDS clusters "
            "when snapshot governance requires inherited tags."
        ),
    )
