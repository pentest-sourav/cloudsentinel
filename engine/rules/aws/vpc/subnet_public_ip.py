from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SubnetPublicIPResult:
    subnet_id: str
    vpc_id: str | None
    map_public_ip_on_launch: bool


def check_subnet_public_ip(
    subnet_id: str,
    vpc_id: str | None,
    map_public_ip_on_launch: bool,
) -> SubnetPublicIPResult | None:
    if not map_public_ip_on_launch:
        return None

    return SubnetPublicIPResult(
        subnet_id=subnet_id,
        vpc_id=vpc_id,
        map_public_ip_on_launch=map_public_ip_on_launch,
    )


def build_subnet_public_ip_finding(
    result: SubnetPublicIPResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-008",
        title="VPC subnet automatically assigns public IPv4 addresses",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="subnet",
        resource_id=result.subnet_id,
        description=(
            "The subnet is configured to automatically assign public "
            "IPv4 addresses to network interfaces launched into it. "
            "AWS Security Hub EC2.15 requires this setting to be disabled."
        ),
        evidence={
            "subnet_id": result.subnet_id,
            "vpc_id": result.vpc_id,
            "map_public_ip_on_launch": result.map_public_ip_on_launch,
        },
        remediation=(
            "Disable automatic public IPv4 address assignment for the "
            "subnet unless the subnet intentionally requires public "
            "IPv4 addressing."
        ),
        compliance=["AWS Security Hub EC2.15"],
    )
