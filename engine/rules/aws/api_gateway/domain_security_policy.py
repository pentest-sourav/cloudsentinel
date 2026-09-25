from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


RECOMMENDED_SECURITY_POLICIES = {
    "SecurityPolicy_TLS13_1_3_2025_09",
    "SecurityPolicy_TLS13_1_3_FIPS_2025_09",
    "SecurityPolicy_TLS13_1_2_PFS_PQ_2025_09",
    "SecurityPolicy_TLS13_2025_EDGE",
    "SecurityPolicy_TLS12_PFS_2025_EDGE",
}


def check_api_gateway_domain_security_policy(
    resource_id: str,
    resource_arn: str,
    security_policy: str | None,
    resource: dict,
) -> dict | None:
    if security_policy in RECOMMENDED_SECURITY_POLICIES:
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "security_policy": security_policy,
            "recommended_security_policies": sorted(
                RECOMMENDED_SECURITY_POLICIES
            ),
        },
    }


def build_api_gateway_domain_security_policy_finding(
    result: dict,
):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-011",
        title=(
            "API Gateway Domain Name Does Not Use "
            "a Recommended Security Policy"
        ),
        severity=Severity.MEDIUM,
        resource_type="api_gateway_domain_name",
        result=result,
        description=(
            "The API Gateway domain name is not configured with "
            "one of the current recommended TLS security policies."
        ),
        remediation=(
            "Update the API Gateway domain name to use one of the "
            "recommended current SecurityPolicy_* TLS policies."
        ),
        compliance="AWS Security Hub APIGateway.11",
    )
