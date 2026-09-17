from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PublicEC2ExposureResult:
    """
    Result of detecting an EC2 instance with a public IPv4 address.
    """

    instance_id: str
    public_ip: str

    @property
    def is_exposed(self) -> bool:
        return True


def check_public_ec2_exposure(
    instance_id: str,
    public_ip: str | None,
) -> PublicEC2ExposureResult | None:
    """
    Detect an EC2 instance that has a public IPv4 address.

    A public IP means the instance has a directly reachable
    public network address. This rule does not determine whether
    a security group actually permits inbound traffic.
    """

    if not public_ip:
        return None

    return PublicEC2ExposureResult(
        instance_id=instance_id,
        public_ip=public_ip,
    )


def build_public_ec2_finding(
    result: PublicEC2ExposureResult,
) -> Finding:
    """
    Convert a public EC2 exposure result into a CloudSentinel Finding.
    """

    return Finding(
        rule_id="CS-AWS-EC2-002",
        title="EC2 Instance Has Public IP Address",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ec2_instance",
        resource_id=result.instance_id,
        description=(
            f"The EC2 instance {result.instance_id} has the public "
            f"IPv4 address {result.public_ip}. A public IP exposes "
            "the instance to the public internet and increases its "
            "network attack surface."
        ),
        evidence={
            "instance_id": result.instance_id,
            "public_ip": result.public_ip,
            "internet_exposed": True,
        },
        remediation=(
            "Remove the public IP address when direct internet access "
            "is not required. Use private networking and controlled "
            "egress or ingress mechanisms such as a load balancer, "
            "VPN, or bastion architecture where appropriate."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
