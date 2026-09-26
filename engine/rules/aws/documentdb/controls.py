from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DocumentDBControlResult:
    resource_id: str
    resource_type: str
    control: str
    evidence: dict[str, Any]


def _result(
    resource_id: str,
    resource_type: str,
    control: str,
    evidence: dict[str, Any],
) -> DocumentDBControlResult:
    return DocumentDBControlResult(
        resource_id=resource_id,
        resource_type=resource_type,
        control=control,
        evidence=evidence,
    )


def _finding(
    result: DocumentDBControlResult,
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
# DocumentDB.1 — Encryption at rest
# ---------------------------------------------------------------------


def check_documentdb_encryption(
    db_cluster_id: str,
    storage_encrypted: bool | None,
) -> DocumentDBControlResult | None:
    if not db_cluster_id or storage_encrypted is None:
        return None

    if storage_encrypted:
        return None

    return _result(
        db_cluster_id,
        "documentdb_cluster",
        "encryption_at_rest",
        {
            "db_cluster_id": db_cluster_id,
            "storage_encrypted": False,
        },
    )


def build_documentdb_encryption_finding(
    result: DocumentDBControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-DOCUMENTDB-001",
        "DocumentDB Cluster Encryption at Rest Is Disabled",
        Severity.MEDIUM,
        (
            f"DocumentDB cluster {result.resource_id} does not have "
            "encryption at rest enabled."
        ),
        (
            "Enable encryption at rest for the DocumentDB cluster using "
            "an appropriate AWS KMS key."
        ),
    )


# ---------------------------------------------------------------------
# DocumentDB.2 — Backup retention
# ---------------------------------------------------------------------


def check_documentdb_backup_retention(
    db_cluster_id: str,
    backup_retention_period: int | None,
) -> DocumentDBControlResult | None:
    if not db_cluster_id or backup_retention_period is None:
        return None

    if backup_retention_period >= 7:
        return None

    return _result(
        db_cluster_id,
        "documentdb_cluster",
        "backup_retention",
        {
            "db_cluster_id": db_cluster_id,
            "backup_retention_period": backup_retention_period,
            "minimum_required_days": 7,
        },
    )


def build_documentdb_backup_retention_finding(
    result: DocumentDBControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-DOCUMENTDB-002",
        "DocumentDB Cluster Backup Retention Is Too Short",
        Severity.MEDIUM,
        (
            f"DocumentDB cluster {result.resource_id} has a backup "
            "retention period shorter than 7 days."
        ),
        (
            "Configure at least 7 days of automated backup retention "
            "for the DocumentDB cluster."
        ),
    )


# ---------------------------------------------------------------------
# DocumentDB.3 — Manual cluster snapshots must not be public
# ---------------------------------------------------------------------


def check_documentdb_snapshot_private(
    snapshot_id: str,
    shared_accounts: list[str] | None,
) -> DocumentDBControlResult | None:
    if not snapshot_id or shared_accounts is None:
        return None

    if "all" not in {str(value).strip().lower() for value in shared_accounts}:
        return None

    return _result(
        snapshot_id,
        "documentdb_cluster_snapshot",
        "snapshot_private",
        {
            "snapshot_id": snapshot_id,
            "shared_accounts": list(shared_accounts),
            "public_access": True,
        },
    )


def build_documentdb_snapshot_private_finding(
    result: DocumentDBControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-DOCUMENTDB-003",
        "DocumentDB Manual Cluster Snapshot Is Publicly Shared",
        Severity.CRITICAL,
        (
            f"DocumentDB manual cluster snapshot {result.resource_id} "
            "is publicly accessible through restore permissions."
        ),
        (
            "Remove the public restore permission from the manual "
            "DocumentDB cluster snapshot and keep snapshots private."
        ),
    )


# ---------------------------------------------------------------------
# DocumentDB.4 — Audit logs to CloudWatch Logs
# ---------------------------------------------------------------------


def check_documentdb_audit_logs(
    db_cluster_id: str,
    enabled_cloudwatch_logs_exports: list[str] | None,
) -> DocumentDBControlResult | None:
    if not db_cluster_id or enabled_cloudwatch_logs_exports is None:
        return None

    normalized = {
        str(value).strip().lower()
        for value in enabled_cloudwatch_logs_exports
        if str(value).strip()
    }

    if "audit" in normalized:
        return None

    return _result(
        db_cluster_id,
        "documentdb_cluster",
        "audit_logs",
        {
            "db_cluster_id": db_cluster_id,
            "enabled_cloudwatch_logs_exports": sorted(normalized),
            "audit_logs_enabled": False,
        },
    )


def build_documentdb_audit_logs_finding(
    result: DocumentDBControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-DOCUMENTDB-004",
        "DocumentDB Audit Logs Are Not Published to CloudWatch Logs",
        Severity.MEDIUM,
        (
            f"DocumentDB cluster {result.resource_id} does not publish "
            "audit logs to CloudWatch Logs."
        ),
        (
            "Enable the DocumentDB audit log export to CloudWatch Logs "
            "for security monitoring and investigation."
        ),
    )


# ---------------------------------------------------------------------
# DocumentDB.5 — Deletion protection
# ---------------------------------------------------------------------


def check_documentdb_deletion_protection(
    db_cluster_id: str,
    deletion_protection: bool | None,
) -> DocumentDBControlResult | None:
    if not db_cluster_id or deletion_protection is None:
        return None

    if deletion_protection:
        return None

    return _result(
        db_cluster_id,
        "documentdb_cluster",
        "deletion_protection",
        {
            "db_cluster_id": db_cluster_id,
            "deletion_protection": False,
        },
    )


def build_documentdb_deletion_protection_finding(
    result: DocumentDBControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-DOCUMENTDB-005",
        "DocumentDB Cluster Deletion Protection Is Disabled",
        Severity.MEDIUM,
        (
            f"DocumentDB cluster {result.resource_id} does not have "
            "deletion protection enabled."
        ),
        (
            "Enable deletion protection for DocumentDB clusters where "
            "accidental deletion must be prevented."
        ),
    )


# ---------------------------------------------------------------------
# DocumentDB.6 — Encryption in transit / TLS
# ---------------------------------------------------------------------


_ALLOWED_TLS_VALUES = {
    "tls1.2+",
    "tls1.3+",
    "fips-140-3",
}


def check_documentdb_tls(
    db_cluster_id: str,
    parameter_group_name: str | None,
    parameter_apply_status: str | None,
    tls_parameter: str | None,
) -> DocumentDBControlResult | None:
    if not db_cluster_id:
        return None

    # AWS Security Hub fails the control when the cluster parameter group
    # is not in sync or when the effective tls parameter is disabled/enabled.
    if not parameter_group_name:
        return _result(
            db_cluster_id,
            "documentdb_cluster",
            "encryption_in_transit",
            {
                "db_cluster_id": db_cluster_id,
                "parameter_group_name": parameter_group_name,
                "parameter_apply_status": parameter_apply_status,
                "tls_parameter": tls_parameter,
                "parameter_group_in_sync": False,
            },
        )

    if str(parameter_apply_status or "").lower() != "in-sync":
        return _result(
            db_cluster_id,
            "documentdb_cluster",
            "encryption_in_transit",
            {
                "db_cluster_id": db_cluster_id,
                "parameter_group_name": parameter_group_name,
                "parameter_apply_status": parameter_apply_status,
                "tls_parameter": tls_parameter,
                "parameter_group_in_sync": False,
            },
        )

    normalized_tls = (
        str(tls_parameter).strip().lower()
        if tls_parameter is not None
        else None
    )

    if normalized_tls in _ALLOWED_TLS_VALUES:
        return None

    return _result(
        db_cluster_id,
        "documentdb_cluster",
        "encryption_in_transit",
        {
            "db_cluster_id": db_cluster_id,
            "parameter_group_name": parameter_group_name,
            "parameter_apply_status": parameter_apply_status,
            "tls_parameter": normalized_tls,
            "parameter_group_in_sync": True,
        },
    )


def build_documentdb_tls_finding(
    result: DocumentDBControlResult,
) -> Finding:
    return _finding(
        result,
        "CS-AWS-DOCUMENTDB-006",
        "DocumentDB Cluster Encryption in Transit Is Not Securely Configured",
        Severity.MEDIUM,
        (
            f"DocumentDB cluster {result.resource_id} does not have a "
            "compliant TLS configuration or its cluster parameter group "
            "is not in sync."
        ),
        (
            "Ensure the associated cluster parameter group is in sync and "
            "configure the tls parameter to tls1.2+, tls1.3+, or "
            "fips-140-3 as supported by the cluster engine version and region."
        ),
    )
