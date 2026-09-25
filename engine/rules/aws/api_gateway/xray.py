from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


def check_api_gateway_xray(
    resource_id: str,
    resource_arn: str,
    tracing_enabled: bool | None,
    resource: dict,
) -> dict | None:
    if tracing_enabled is True:
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "tracing_enabled": tracing_enabled,
        },
    }


def build_api_gateway_xray_finding(result: dict):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-003",
        title="API Gateway REST Stage Does Not Have X-Ray Tracing Enabled",
        severity=Severity.LOW,
        resource_type="api_gateway_rest_stage",
        result=result,
        description=(
            "The API Gateway REST API stage does not have "
            "AWS X-Ray active tracing enabled."
        ),
        remediation=(
            "Enable AWS X-Ray active tracing for the REST API stage."
        ),
        compliance="AWS Security Hub APIGateway.3",
    )
