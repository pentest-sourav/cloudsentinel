from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class UnusedElasticIPResult:
    """
    Result of evaluating an Elastic IP association.
    """

    allocation_id: str
    public_ip: str | None


def check_unused_elastic_ip(
    allocation_id: str,
    public_ip: str | None,
    instance_id: str | None,
    network_interface_id: str | None,
    associated: bool,
) -> UnusedElasticIPResult | None:
    """
    Detect an allocated Elastic IP that is not associated
    with an EC2 instance or network interface.
    """

    if associated:
        return None

    return UnusedElasticIPResult(
        allocation_id=allocation_id,
        public_ip=public_ip,
    )


def build_unused_elastic_ip_finding(
    result: UnusedElasticIPResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-007",
        title="Unused Elastic IP Address",
        severity=Severity.LOW,
        provider="aws",
        resource_type="ec2_elastic_ip",
        resource_id=result.allocation_id,
        description=(
            f"The Elastic IP allocation {result.allocation_id} "
            f"({result.public_ip}) is not associated with an "
            "EC2 instance or network interface. Unused public "
            "addresses increase unnecessary internet-facing "
            "resource inventory and may incur AWS charges."
        ),
        evidence={
            "allocation_id": result.allocation_id,
            "public_ip": result.public_ip,
            "associated": False,
        },
        remediation=(
            "Release the Elastic IP address if it is no longer "
            "required. If it is reserved intentionally, associate "
            "it with the intended resource."
        ),
        compliance=[
            "AWS Security Hub EC2.12",
        ],
    )
