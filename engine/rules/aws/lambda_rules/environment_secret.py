from dataclasses import dataclass

from engine.findings.model import Finding, Severity


_SECRET_NAME_PATTERNS = (
    "ACCESS_KEY",
    "SECRET_KEY",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "API_SECRET",
    "AUTH_TOKEN",
    "ACCESS_TOKEN",
    "PRIVATE_KEY",
    "JWT_SECRET",
    "CLIENT_SECRET",
    "DATABASE_PASSWORD",
    "DB_PASSWORD",
)


@dataclass(frozen=True)
class LambdaEnvironmentSecretResult:
    function_name: str
    variable_name: str
    matched_pattern: str


def _find_secret_like_variable(
    environment_variables: dict[str, object] | None,
) -> tuple[str, str] | None:
    if not isinstance(environment_variables, dict):
        return None

    for variable_name in environment_variables:
        if not isinstance(variable_name, str):
            continue

        normalized_name = variable_name.upper()

        for pattern in _SECRET_NAME_PATTERNS:
            if pattern in normalized_name:
                return variable_name, pattern

    return None


def check_lambda_environment_secret(
    function_name: str,
    environment_variables: dict[str, object] | None,
) -> LambdaEnvironmentSecretResult | None:
    """
    Detect Lambda environment variable names that strongly suggest
    credentials or secrets are being stored in Lambda configuration.

    The variable value is intentionally never inspected or returned.
    """
    match = _find_secret_like_variable(environment_variables)

    if match is None:
        return None

    variable_name, matched_pattern = match

    return LambdaEnvironmentSecretResult(
        function_name=function_name,
        variable_name=variable_name,
        matched_pattern=matched_pattern,
    )


def build_lambda_environment_secret_finding(
    result: LambdaEnvironmentSecretResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-LAMBDA-008",
        title="Lambda environment variable may contain a secret",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_name,
        description=(
            "The Lambda function contains an environment variable whose "
            "name suggests it may store a credential, secret, password, "
            "token, or private key. Environment variables are not a "
            "preferred location for long-lived secrets."
        ),
        evidence={
            "function_name": result.function_name,
            "variable_name": result.variable_name,
            "matched_pattern": result.matched_pattern,
        },
        remediation=(
            "Move sensitive values out of Lambda environment variables "
            "and store them in a dedicated secrets-management service "
            "such as AWS Secrets Manager or AWS Systems Manager "
            "Parameter Store. Grant the function least-privilege "
            "access to retrieve the required secret at runtime."
        ),
    )
