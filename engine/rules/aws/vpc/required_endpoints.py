from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RequiredEndpointResult:
    vpc_id: str
    region: str | None
    service_name: str
    endpoint_type: str | None


def check_required_endpoint(
    vpc_id: str,
    region: str | None,
    service_name: str,
    endpoint_type: str | None,
    endpoint_enabled: bool,
) -> RequiredEndpointResult | None:
    if endpoint_enabled:
        return None

    return RequiredEndpointResult(
        vpc_id=vpc_id,
        region=region,
        service_name=service_name,
        endpoint_type=endpoint_type,
    )


def build_required_endpoint_finding(
    result: RequiredEndpointResult,
    rule_id: str,
    title: str,
    compliance: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="vpc",
        resource_id=result.vpc_id,
        description=(
            f"The VPC does not have the required interface VPC "
            f"endpoint for {result.service_name}. AWS Security Hub "
            f"requires private access to this service through a VPC "
            f"interface endpoint."
        ),
        evidence={
            "vpc_id": result.vpc_id,
            "region": result.region,
            "service_name": result.service_name,
            "endpoint_type": result.endpoint_type,
            "endpoint_enabled": False,
        },
        remediation=(
            f"Create an interface VPC endpoint for "
            f"{result.service_name} in the affected VPC. "
            f"Ensure the endpoint is configured for the required "
            f"private service access pattern."
        ),
        compliance=[compliance],
    )


def build_ecr_api_endpoint_finding(
    result: RequiredEndpointResult,
) -> Finding:
    return build_required_endpoint_finding(
        result,
        "CS-AWS-VPC-011",
        "VPC is missing an ECR API interface endpoint",
        "AWS Security Hub EC2.55",
    )


def build_ecr_dkr_endpoint_finding(
    result: RequiredEndpointResult,
) -> Finding:
    return build_required_endpoint_finding(
        result,
        "CS-AWS-VPC-012",
        "VPC is missing an ECR Docker Registry interface endpoint",
        "AWS Security Hub EC2.56",
    )


def build_ssm_endpoint_finding(
    result: RequiredEndpointResult,
) -> Finding:
    return build_required_endpoint_finding(
        result,
        "CS-AWS-VPC-013",
        "VPC is missing a Systems Manager interface endpoint",
        "AWS Security Hub EC2.57",
    )


def build_ssm_contacts_endpoint_finding(
    result: RequiredEndpointResult,
) -> Finding:
    return build_required_endpoint_finding(
        result,
        "CS-AWS-VPC-014",
        "VPC is missing a Systems Manager Contacts interface endpoint",
        "AWS Security Hub EC2.58",
    )


def build_ssm_incidents_endpoint_finding(
    result: RequiredEndpointResult,
) -> Finding:
    return build_required_endpoint_finding(
        result,
        "CS-AWS-VPC-015",
        "VPC is missing a Systems Manager Incident Manager interface endpoint",
        "AWS Security Hub EC2.60",
    )
