from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


def check_api_gateway_backend_ssl(
    resource_id: str,
    resource_arn: str,
    client_certificate_id: str | None,
    has_http_integration: bool,
    resource: dict,
) -> dict | None:
    if not has_http_integration:
        return None

    if client_certificate_id:
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "client_certificate_id": client_certificate_id,
            "has_http_integration": has_http_integration,
        },
    }


def build_api_gateway_backend_ssl_finding(result: dict):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-002",
        title=(
            "API Gateway REST Stage Does Not Use "
            "an SSL Certificate for Backend Authentication"
        ),
        severity=Severity.MEDIUM,
        resource_type="api_gateway_rest_stage",
        result=result,
        description=(
            "The REST API stage has an HTTP integration but "
            "does not have a client SSL certificate configured "
            "for backend authentication."
        ),
        remediation=(
            "Configure a client certificate on the REST API stage "
            "for backend authentication."
        ),
        compliance="AWS Security Hub APIGateway.2",
    )
