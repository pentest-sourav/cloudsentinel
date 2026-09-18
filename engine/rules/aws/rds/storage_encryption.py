from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSStorageEncryptionResult:
    db_instance_id: str


def check_rds_storage_encryption(
    db_instance_id: str,
    storage_encrypted: bool,
) -> RDSStorageEncryptionResult | None:
    if not db_instance_id:
        return None

    if storage_encrypted:
        return None

    return RDSStorageEncryptionResult(
        db_instance_id=db_instance_id,
    )


def build_rds_storage_encryption_finding(
    result: RDSStorageEncryptionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RDS-002",
        title="RDS Storage Encryption Is Disabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS instance {result.db_instance_id} "
            "does not have storage encryption enabled. "
            "Unencrypted database storage can expose sensitive data "
            "if the underlying storage or snapshots are accessed."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "storage_encrypted": False,
            "sensitive_data": True,
        },
        remediation=(
            "Enable storage encryption for the RDS instance using "
            "an appropriate AWS KMS key. For existing RDS instances, "
            "follow AWS-supported migration procedures because "
            "storage encryption cannot simply be enabled in place."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
