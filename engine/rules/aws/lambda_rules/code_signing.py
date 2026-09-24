from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class LambdaCodeSigningResult:
    function_name: str
    code_signing_config_arn: str | None
    code_signing_policy: dict[str, Any] | None


def _get_untrusted_artifact_policy(
    code_signing_policy: dict[str, Any] | None,
) -> str | None:
    if not isinstance(code_signing_policy, dict):
        return None

    value = code_signing_policy.get("UntrustedArtifactOnDeployment")

    if not isinstance(value, str):
        return None

    return value


def check_lambda_code_signing(
    function_name: str,
    package_type: str | None,
    code_signing_config_arn: str | None,
    code_signing_policy: dict[str, Any] | None,
) -> LambdaCodeSigningResult | None:
    """
    Detect ZIP-based Lambda functions that do not enforce code signing.

    Container-image functions are excluded because Lambda Code Signing
    Configuration applies to ZIP deployment packages.
    """
    if package_type == "Image":
        return None

    enforcement = _get_untrusted_artifact_policy(code_signing_policy)

    if code_signing_config_arn and enforcement == "Enforce":
        return None

    return LambdaCodeSigningResult(
        function_name=function_name,
        code_signing_config_arn=code_signing_config_arn,
        code_signing_policy=code_signing_policy,
    )


def build_lambda_code_signing_finding(
    result: LambdaCodeSigningResult,
) -> Finding:
    enforcement = _get_untrusted_artifact_policy(
        result.code_signing_policy
    )

    return Finding(
        rule_id="CS-AWS-LAMBDA-007",
        title="Lambda function does not enforce code signing",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="lambda_function",
        resource_id=result.function_name,
        description=(
            "The Lambda function does not have an enforced Code Signing "
            "Configuration. Unsigned or untrusted deployment artifacts "
            "may therefore be accepted."
        ),
        evidence={
            "function_name": result.function_name,
            "code_signing_config_arn": result.code_signing_config_arn,
            "untrusted_artifact_on_deployment": enforcement,
            "code_signing_enforced": enforcement == "Enforce",
        },
        remediation=(
            "Associate a Lambda Code Signing Configuration with the "
            "function and configure UntrustedArtifactOnDeployment as "
            "Enforce. Configure trusted signing profiles appropriate "
            "for the deployment pipeline."
        ),
    )
