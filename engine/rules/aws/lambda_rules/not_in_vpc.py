from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class LambdaNotInVPCResult:
    function_name: str
    vpc_id: str | None
    subnet_ids: list[str]


def check_lambda_not_in_vpc(
    function_name: str,
    vpc_id: str | None,
    subnet_ids: list[str],
) -> LambdaNotInVPCResult | None:
    """
    Detect Lambda functions that are not configured for a
    customer-managed VPC.
    """
    if vpc_id and subnet_ids:
        return None

    return LambdaNotInVPCResult(
        function_name=function_name,
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
    )


def build_lambda_not_in_vpc_finding(
    result: LambdaNotInVPCResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-LAMBDA-004",
        title="Lambda function is not deployed in a VPC",
        severity=Severity.LOW,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_name,
        description=(
            "The Lambda function is not configured to access resources "
            "through a customer-managed VPC."
        ),
        evidence={
            "function_name": result.function_name,
            "vpc_id": result.vpc_id,
            "subnet_ids": result.subnet_ids,
            "vpc_configured": False,
        },
        remediation=(
            "Configure the Lambda function with appropriate VPC "
            "subnets and security groups when network isolation is "
            "required by the workload."
        ),
    )
