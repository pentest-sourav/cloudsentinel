from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EC2VPCEndpointResult:
    vpc_id: str
    region: str | None


def check_ec2_vpc_endpoint(
    vpc_id: str,
    region: str | None,
    ec2_endpoint_enabled: bool,
) -> EC2VPCEndpointResult | None:
    if ec2_endpoint_enabled:
        return None

    return EC2VPCEndpointResult(
        vpc_id=vpc_id,
        region=region,
    )


def build_ec2_vpc_endpoint_finding(
    result: EC2VPCEndpointResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-006",
        title="VPC does not have an Amazon EC2 VPC endpoint",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="vpc",
        resource_id=result.vpc_id,
        description=(
            "The VPC does not have an Amazon EC2 interface VPC endpoint. "
            "An EC2 VPC endpoint provides private connectivity to the "
            "Amazon EC2 API without requiring internet-based access."
        ),
        evidence={
            "vpc_id": result.vpc_id,
            "region": result.region,
            "ec2_endpoint_enabled": False,
        },
        remediation=(
            "Create an interface VPC endpoint for the regional Amazon EC2 "
            "service in the VPC. Use the regional EC2 service name "
            "com.amazonaws.<region>.ec2."
        ),
        compliance=[
            "AWS Security Hub EC2.10",
        ],
    )
