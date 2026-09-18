from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RDSPublicAccessResult:
    """
    Result of evaluating whether an RDS instance
    is publicly accessible.
    """

    db_instance_id: str


def check_public_rds(
    db_instance_id: str,
    publicly_accessible: bool,
) -> RDSPublicAccessResult | None:
    """
    Detect an RDS DB instance configured for public access.

    The rule evaluates normalized collector data only.
    It does not perform AWS API calls or remediation.
    """
    if not db_instance_id:
        return None

    if not publicly_accessible:
        return None

    return RDSPublicAccessResult(
        db_instance_id=db_instance_id,
    )


def build_public_rds_finding(
    result: RDSPublicAccessResult,
) -> Finding:
    """
    Convert a public RDS result into a CloudSentinel finding.
    """
    return Finding(
        rule_id="CS-AWS-RDS-001",
        title="RDS Instance Is Publicly Accessible",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="rds_instance",
        resource_id=result.db_instance_id,
        description=(
            f"The RDS instance {result.db_instance_id} "
            "is configured to be publicly accessible. "
            "Publicly accessible database instances can "
            "increase the risk of unauthorized network access."
        ),
        evidence={
            "db_instance_id": result.db_instance_id,
            "publicly_accessible": True,
            "internet_exposed": True,
        },
        remediation=(
            "Disable public accessibility for the RDS instance "
            "unless public database access is explicitly required. "
            "Prefer private subnets and restrict database access "
            "through appropriate network security controls."
        ),
        compliance=["CIS AWS Foundations"],
    )
