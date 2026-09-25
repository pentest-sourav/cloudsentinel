from engine.findings.model import Severity

from engine.rules.aws.api_gateway.common import build_finding


def check_api_gateway_cache_encryption(
    resource_id: str,
    resource_arn: str,
    method_settings: dict,
    cache_cluster_enabled: bool | None,
    resource: dict,
) -> dict | None:
    if cache_cluster_enabled is not True:
        return None

    insecure_methods = []

    for method_path, settings in method_settings.items():
        if not isinstance(settings, dict):
            continue

        caching_enabled = settings.get("cachingEnabled")

        if caching_enabled is not True:
            continue

        if settings.get("cacheDataEncrypted") is not True:
            insecure_methods.append(method_path)

    if not insecure_methods:
        return None

    return {
        "resource_id": resource_id,
        "evidence": {
            "resource_arn": resource_arn,
            "cache_cluster_enabled": cache_cluster_enabled,
            "insecure_methods": insecure_methods,
        },
    }


def build_api_gateway_cache_encryption_finding(result: dict):
    return build_finding(
        rule_id="CS-AWS-APIGATEWAY-005",
        title="API Gateway REST API Cache Data Is Not Encrypted",
        severity=Severity.MEDIUM,
        resource_type="api_gateway_rest_stage",
        result=result,
        description=(
            "One or more cached API Gateway REST API methods "
            "have caching enabled without cache encryption."
        ),
        remediation=(
            "Enable cache data encryption for every REST API "
            "method that has caching enabled."
        ),
        compliance="AWS Security Hub APIGateway.5",
    )
