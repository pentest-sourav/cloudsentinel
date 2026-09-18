from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSDeletionProtectionResult:
    db_instance_id: str


def check_rds_deletion_protection(
    db_instance_id: str,
    deletion_protection: bool,
) -> RDSDeletionProtectionResult | None:
    if not db_instance_id:
        return None

    if deletion_protection:
        return None

    return RDSDeletionProtectionResult(
        db_instance_id=db_instance_id,
    )


def build_rds_deletion_protection_finding(
    result: RDSDeletionProtectionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RDS-005",
        title="RDS Deletion Protection Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS instance {result.db_instance_id} "
            "does not have deletion protection enabled. "
            "Without deletion protection, an RDS instance may be "
            "deleted accidentally or by an unauthorized operation."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "deletion_protection": False,
        },
        remediation=(
            "Enable deletion protection for the RDS instance "
            "when accidental deletion prevention is required."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
