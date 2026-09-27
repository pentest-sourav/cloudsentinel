from typing import Any


RULE_ID = "CS-AWS-VPC-006"


def check_ec2_vpc_endpoint(
    vpc_id: str,
    region: str | None,
    ec2_endpoint_enabled: bool,
) -> bool:
    """
    Pass when the VPC has an Amazon EC2 service endpoint.

    The collector has already normalized both standard and FIPS
    regional EC2 endpoint service names into ec2_endpoint_enabled.
    """
    del vpc_id
    del region

    return bool(ec2_endpoint_enabled)


def build_ec2_vpc_endpoint_finding(
    vpc_id: str,
    region: str | None,
    ec2_endpoint_enabled: bool,
) -> dict[str, Any]:
    return {
        "rule_id": RULE_ID,
        "resource_id": vpc_id,
        "resource_type": "AWS::EC2::VPC",
        "severity": "MEDIUM",
        "title": (
            "VPC should have an Amazon EC2 service endpoint"
        ),
        "description": (
            "The VPC does not have an Amazon EC2 VPC endpoint. "
            "An interface VPC endpoint provides private connectivity "
            "to the Amazon EC2 API without requiring internet "
            "gateway or NAT-based access."
        ),
        "region": region,
        "ec2_endpoint_enabled": bool(
            ec2_endpoint_enabled
        ),
    }
