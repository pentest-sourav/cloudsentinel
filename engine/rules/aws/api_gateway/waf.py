from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


def check_api_gateway_waf(
    resource_id: str,
    resource_arn: str,
    waf_arn: str | None,
    resource: dict,
) -> dict | None:
    if waf_arn:
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "waf_arn": waf_arn,
        },
    }


def build_api_gateway_waf_finding(result: dict):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-004",
        title="API Gateway REST Stage Is Not Associated With AWS WAF",
        severity=Severity.MEDIUM,
        resource_type="api_gateway_rest_stage",
        result=result,
        description=(
            "The API Gateway REST API stage does not have "
            "an AWS WAF Web ACL associated with it."
        ),
        remediation=(
            "Associate an AWS WAF Web ACL with the REST API stage."
        ),
        compliance="AWS Security Hub APIGateway.4",
    )
