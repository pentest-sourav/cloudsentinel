from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSMultiAZResult:
    db_instance_id: str


def check_rds_multi_az(
    db_instance_id: str,
    multi_az: bool,
) -> RDSMultiAZResult | None:
    if not db_instance_id:
        return None

    if multi_az:
        return None

    return RDSMultiAZResult(
        db_instance_id=db_instance_id,
    )


def build_rds_multi_az_finding(
    result: RDSMultiAZResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-RDS-004",
        title="RDS Multi-AZ Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS instance {result.db_instance_id} "
            "does not have Multi-AZ enabled. "
            "Without Multi-AZ deployment, the database may have "
            "reduced resilience against an Availability Zone failure."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "multi_az": False,
            "availability_resilience": "reduced",
        },
        remediation=(
            "Enable Multi-AZ deployment for the RDS instance "
            "when the application's availability requirements "
            "require resilience across Availability Zones."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
