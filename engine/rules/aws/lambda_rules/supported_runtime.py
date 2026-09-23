from dataclasses import dataclass

from engine.findings.model import Finding, Severity


SUPPORTED_LAMBDA_RUNTIMES = frozenset(
    {
        "dotnet10",
        "dotnet8",
        "java25",
        "java21",
        "java17",
        "java11",
        "java8.al2",
        "java17.al2023",
        "java11.al2023",
        "java8.al2023",
        "nodejs24.x",
        "nodejs22.x",
        "python3.14",
        "python3.13",
        "python3.12",
        "python3.11",
        "python3.10",
        "ruby4.0",
        "ruby3.4",
        "ruby3.3",
    }
)


@dataclass(frozen=True)
class UnsupportedLambdaRuntimeResult:
    function_name: str
    runtime: str | None
    package_type: str | None


def check_unsupported_lambda_runtime(
    function_name: str,
    runtime: str | None,
    package_type: str | None,
) -> UnsupportedLambdaRuntimeResult | None:
    """
    Detect Lambda functions using a runtime outside the current
    AWS Security Hub supported-runtime set.

    Container-image functions are intentionally excluded because their
    runtime is defined by the image rather than a managed Lambda runtime.
    """
    if package_type == "Image":
        return None

    if runtime in SUPPORTED_LAMBDA_RUNTIMES:
        return None

    return UnsupportedLambdaRuntimeResult(
        function_name=function_name,
        runtime=runtime,
        package_type=package_type,
    )


def build_unsupported_lambda_runtime_finding(
    result: UnsupportedLambdaRuntimeResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-LAMBDA-003",
        title="Lambda function uses an unsupported runtime",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_name,
        description=(
            "The Lambda function uses a runtime that is not in the "
            "currently supported AWS Lambda managed-runtime set."
        ),
        evidence={
            "function_name": result.function_name,
            "runtime": result.runtime,
            "package_type": result.package_type,
            "supported_runtime": False,
        },
        remediation=(
            "Migrate the function to a currently supported Lambda "
            "managed runtime. For container-image functions, manage "
            "the runtime lifecycle through the container base image "
            "and dependency stack."
        ),
    )
