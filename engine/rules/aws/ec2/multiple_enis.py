from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class MultipleENIResult:
    """
    Result of evaluating the number of network interfaces
    attached to an EC2 instance.
    """

    instance_id: str
    network_interface_count: int


def check_multiple_enis(
    instance_id: str,
    network_interface_count: int,
) -> MultipleENIResult | None:
    """
    Detect EC2 instances using more than one network interface.
    """

    if network_interface_count <= 1:
        return None

    return MultipleENIResult(
        instance_id=instance_id,
        network_interface_count=network_interface_count,
    )


def build_multiple_enis_finding(
    result: MultipleENIResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-008",
        title="EC2 Instance Uses Multiple Network Interfaces",
        severity=Severity.LOW,
        provider="aws",
        resource_type="ec2_instance",
        resource_id=result.instance_id,
        description=(
            f"The EC2 instance {result.instance_id} has "
            f"{result.network_interface_count} network interfaces. "
            "Multiple interfaces can create additional network "
            "paths and increase network security complexity."
        ),
        evidence={
            "instance_id": result.instance_id,
            "network_interface_count": (
                result.network_interface_count
            ),
        },
        remediation=(
            "Review every attached network interface and remove "
            "interfaces that are not required. If multiple ENIs "
            "are intentional, document and validate the resulting "
            "network paths."
        ),
        compliance=[
            "AWS Security Hub EC2.17",
        ],
    )
