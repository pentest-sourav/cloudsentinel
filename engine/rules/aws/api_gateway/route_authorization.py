from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


def check_api_gateway_route_authorization(
    resource_id: str,
    resource_arn: str,
    authorization_type: str | None,
    resource: dict,
) -> dict | None:
    if authorization_type and authorization_type != "NONE":
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "authorization_type": authorization_type,
        },
    }


def build_api_gateway_route_authorization_finding(result: dict):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-008",
        title="API Gateway V2 Route Does Not Specify Authorization",
        severity=Severity.MEDIUM,
        resource_type="api_gateway_v2_route",
        result=result,
        description=(
            "The API Gateway V2 route uses NONE or does not "
            "specify an authorization type."
        ),
        remediation=(
            "Configure an authorization type such as AWS_IAM, "
            "CUSTOM, or JWT for the route."
        ),
        compliance="AWS Security Hub APIGateway.8",
    )
