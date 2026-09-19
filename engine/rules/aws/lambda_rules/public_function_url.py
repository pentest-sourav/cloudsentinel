from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class PublicLambdaFunctionURLResult:
    function_name: str
    function_url: str


def check_public_lambda_function_url(
    function_name: str,
    function_url: str | None,
    url_auth_type: str | None,
) -> PublicLambdaFunctionURLResult | None:
    """
    Detect Lambda Function URLs configured with public/no authentication.
    """

    if not function_url:
        return None

    if url_auth_type != "NONE":
        return None

    return PublicLambdaFunctionURLResult(
        function_name=function_name,
        function_url=function_url,
    )


def build_public_lambda_function_url_finding(
    result: PublicLambdaFunctionURLResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-LAMBDA-001",
        title="Lambda Function URL allows unauthenticated access",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_name,
        description=(
            "The Lambda function has a Function URL configured with "
            "AuthType NONE. This allows requests to reach the function "
            "without AWS authentication."
        ),
        evidence={
            "function_name": result.function_name,
            "function_url": result.function_url,
            "auth_type": "NONE",
            "internet_exposed": True,
        },
        remediation=(
            "Require authentication for the Lambda Function URL. "
            "Prefer AWS_IAM authentication when appropriate, or remove "
            "the Function URL if public access is not required."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
