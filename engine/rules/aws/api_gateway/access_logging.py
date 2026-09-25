from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


def check_api_gateway_access_logging(
    resource_id: str,
    resource_arn: str,
    access_log_settings: dict,
    resource: dict,
) -> dict | None:
    if access_log_settings:
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "access_log_settings": access_log_settings,
        },
    }


def build_api_gateway_access_logging_finding(result: dict):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-009",
        title="API Gateway V2 Stage Does Not Have Access Logging Configured",
        severity=Severity.MEDIUM,
        resource_type="api_gateway_v2_stage",
        result=result,
        description=(
            "The API Gateway V2 stage does not have accessLogSettings "
            "configured."
        ),
        remediation=(
            "Configure access logging for the API Gateway V2 stage."
        ),
        compliance="AWS Security Hub APIGateway.9",
    )
