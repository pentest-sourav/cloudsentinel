from dataclasses import dataclass

from engine.findings.model import Finding, Severity


MINIMUM_AVAILABILITY_ZONES = 2


@dataclass(frozen=True)
class LambdaVpcMultiAZResult:
    function_name: str
    vpc_id: str | None
    subnet_ids: list[str]
    availability_zones: list[str]


def check_lambda_vpc_multi_az(
    function_name: str,
    vpc_id: str | None,
    subnet_ids: list[str],
    subnet_availability_zones: dict[str, str],
) -> LambdaVpcMultiAZResult | None:
    """
    Detect VPC-connected Lambda functions that do not span at least
    two Availability Zones.

    If subnet-to-AZ enrichment is incomplete, the rule does not emit
    a finding rather than guessing and producing a false positive.
    """
    if not vpc_id or not subnet_ids:
        return None

    if not all(
        subnet_id in subnet_availability_zones
        for subnet_id in subnet_ids
    ):
        return None

    availability_zones = sorted(
        {
            subnet_availability_zones[subnet_id]
            for subnet_id in subnet_ids
            if subnet_availability_zones.get(subnet_id)
        }
    )

    if len(availability_zones) >= MINIMUM_AVAILABILITY_ZONES:
        return None

    return LambdaVpcMultiAZResult(
        function_name=function_name,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        availability_zones=availability_zones,
    )


def build_lambda_vpc_multi_az_finding(
    result: LambdaVpcMultiAZResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-LAMBDA-005",
        title="VPC Lambda function is not deployed across multiple AZs",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_name,
        description=(
            "The VPC-connected Lambda function is configured across "
            "fewer than two Availability Zones."
        ),
        evidence={
            "function_name": result.function_name,
            "vpc_id": result.vpc_id,
            "subnet_ids": result.subnet_ids,
            "availability_zones": result.availability_zones,
            "minimum_availability_zones": (
                MINIMUM_AVAILABILITY_ZONES
            ),
        },
        remediation=(
            "Configure the Lambda function with subnets spanning at "
            "least two Availability Zones to improve resilience "
            "against a single-AZ failure."
        ),
    )
