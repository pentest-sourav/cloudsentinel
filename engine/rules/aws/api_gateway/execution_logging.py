from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


def check_api_gateway_execution_logging(
    resource_id: str,
    resource_arn: str,
    api_protocol_type: str,
    logging_level: str | None,
    resource: dict,
) -> dict | None:
    if logging_level in {"ERROR", "INFO"}:
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "api_protocol_type": api_protocol_type,
            "logging_level": logging_level,
        },
    }


def build_api_gateway_execution_logging_finding(
    result: dict,
):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-001",
        title=(
            "API Gateway REST or WebSocket "
            "Execution Logging Is Not Enabled"
        ),
        severity=Severity.MEDIUM,
        resource_type="api_gateway_stage",
        result=result,
        description=(
            "The API Gateway REST or WebSocket stage does not "
            "have execution logging configured at ERROR or INFO."
        ),
        remediation=(
            "Configure API Gateway execution logging with "
            "logging level ERROR or INFO."
        ),
        compliance="AWS Security Hub APIGateway.1",
    )
