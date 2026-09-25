from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


def check_api_gateway_private_https(
    resource_id: str,
    resource_arn: str,
    protocol_type: str | None,
    connection_type: str | None,
    tls_config: dict,
    resource: dict,
) -> dict | None:
    if protocol_type != "HTTP":
        return None

    if connection_type != "VPC_LINK":
        return None

    if tls_config:
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "protocol_type": protocol_type,
            "connection_type": connection_type,
            "tls_config": tls_config,
        },
    }


def build_api_gateway_private_https_finding(result: dict):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-010",
        title=(
            "API Gateway V2 Private Integration Does Not Use HTTPS"
        ),
        severity=Severity.MEDIUM,
        resource_type="api_gateway_v2_integration",
        result=result,
        description=(
            "An API Gateway V2 HTTP API private integration uses "
            "a VPC link without TLS configuration."
        ),
        remediation=(
            "Configure TlsConfig on the private API Gateway V2 "
            "integration so backend traffic uses HTTPS."
        ),
        compliance="AWS Security Hub APIGateway.10",
    )
