from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


ALLOWED_AUTHORIZATION_TYPES = {
    "AWS_IAM",
    "CUSTOM",
    "JWT",
}


def check_api_gateway_route_authorization(
    resource_id: str,
    resource_arn: str,
    authorization_type: str | None,
    resource: dict,
    required_authorization_type: str | None = None,
) -> dict | None:
    if required_authorization_type is not None:
        if (
            authorization_type
            == required_authorization_type
            and authorization_type
            in ALLOWED_AUTHORIZATION_TYPES
        ):
            return None
    elif (
        authorization_type
        and authorization_type != "NONE"
    ):
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "authorization_type": authorization_type,
            "required_authorization_type": (
                required_authorization_type
            ),
        },
    }


def build_api_gateway_route_authorization_finding(result: dict):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-008",
        title="API Gateway V2 Route Does Not Specify Required Authorization",
        severity=Severity.MEDIUM,
        resource_type="api_gateway_v2_route",
        result=result,
        description=(
            "The API Gateway V2 route does not satisfy the "
            "configured authorization-type requirement."
        ),
        remediation=(
            "Configure an authorization type such as AWS_IAM, "
            "CUSTOM, or JWT for the route."
        ),
        compliance="AWS Security Hub APIGateway.8",
    )
