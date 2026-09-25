from engine.findings.model import Severity

from engine.rules.aws.api_gateway.access_logging import (
    build_api_gateway_access_logging_finding,
    check_api_gateway_access_logging,
)
from engine.rules.aws.api_gateway.backend_ssl import (
    build_api_gateway_backend_ssl_finding,
    check_api_gateway_backend_ssl,
)
from engine.rules.aws.api_gateway.cache_encryption import (
    build_api_gateway_cache_encryption_finding,
    check_api_gateway_cache_encryption,
)
from engine.rules.aws.api_gateway.domain_security_policy import (
    build_api_gateway_domain_security_policy_finding,
    check_api_gateway_domain_security_policy,
)
from engine.rules.aws.api_gateway.execution_logging import (
    build_api_gateway_execution_logging_finding,
    check_api_gateway_execution_logging,
)
from engine.rules.aws.api_gateway.private_https import (
    build_api_gateway_private_https_finding,
    check_api_gateway_private_https,
)
from engine.rules.aws.api_gateway.route_authorization import (
    build_api_gateway_route_authorization_finding,
    check_api_gateway_route_authorization,
)
from engine.rules.aws.api_gateway.waf import (
    build_api_gateway_waf_finding,
    check_api_gateway_waf,
)
from engine.rules.aws.api_gateway.xray import (
    build_api_gateway_xray_finding,
    check_api_gateway_xray,
)


BASE = {
    "resource_id": "resource-1",
    "resource_arn": "arn:aws:test:resource-1",
    "resource": {},
}


def test_execution_logging():
    assert (
        check_api_gateway_execution_logging(
            **BASE,
            api_protocol_type="REST",
            logging_level="ERROR",
        )
        is None
    )

    result = check_api_gateway_execution_logging(
        **BASE,
        api_protocol_type="REST",
        logging_level=None,
    )

    assert result is not None

    finding = build_api_gateway_execution_logging_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-APIGATEWAY-001"
    assert finding.severity == Severity.MEDIUM


def test_backend_ssl_is_not_applicable_without_http_integration():
    assert (
        check_api_gateway_backend_ssl(
            **BASE,
            client_certificate_id=None,
            has_http_integration=False,
        )
        is None
    )


def test_backend_ssl():
    assert (
        check_api_gateway_backend_ssl(
            **BASE,
            client_certificate_id="cert-id",
            has_http_integration=True,
        )
        is None
    )

    result = check_api_gateway_backend_ssl(
        **BASE,
        client_certificate_id=None,
        has_http_integration=True,
    )

    assert result is not None

    finding = build_api_gateway_backend_ssl_finding(result)

    assert finding.rule_id == "CS-AWS-APIGATEWAY-002"


def test_xray():
    assert (
        check_api_gateway_xray(
            **BASE,
            tracing_enabled=True,
        )
        is None
    )

    result = check_api_gateway_xray(
        **BASE,
        tracing_enabled=False,
    )

    assert result is not None

    finding = build_api_gateway_xray_finding(result)

    assert finding.rule_id == "CS-AWS-APIGATEWAY-003"
    assert finding.severity == Severity.LOW


def test_waf():
    assert (
        check_api_gateway_waf(
            **BASE,
            waf_arn="arn:aws:wafv2:test",
        )
        is None
    )

    result = check_api_gateway_waf(
        **BASE,
        waf_arn=None,
    )

    assert result is not None

    finding = build_api_gateway_waf_finding(result)

    assert finding.rule_id == "CS-AWS-APIGATEWAY-004"


def test_cache_encryption():
    settings = {
        "/*/*": {
            "cachingEnabled": True,
            "cacheDataEncrypted": True,
        }
    }

    assert (
        check_api_gateway_cache_encryption(
            **BASE,
            method_settings=settings,
            cache_cluster_enabled=True,
        )
        is None
    )

    insecure = {
        "/*/*": {
            "cachingEnabled": True,
            "cacheDataEncrypted": False,
        }
    }

    result = check_api_gateway_cache_encryption(
        **BASE,
        method_settings=insecure,
        cache_cluster_enabled=True,
    )

    assert result is not None

    finding = build_api_gateway_cache_encryption_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-APIGATEWAY-005"


def test_cache_disabled_is_not_flagged():
    assert (
        check_api_gateway_cache_encryption(
            **BASE,
            method_settings={},
            cache_cluster_enabled=False,
        )
        is None
    )


def test_route_authorization():
    assert (
        check_api_gateway_route_authorization(
            **BASE,
            authorization_type="AWS_IAM",
        )
        is None
    )

    result = check_api_gateway_route_authorization(
        **BASE,
        authorization_type="NONE",
    )

    assert result is not None

    finding = build_api_gateway_route_authorization_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-APIGATEWAY-008"


def test_access_logging():
    assert (
        check_api_gateway_access_logging(
            **BASE,
            access_log_settings={
                "DestinationArn": "arn:aws:logs:test",
                "Format": "$context.requestId",
            },
        )
        is None
    )

    result = check_api_gateway_access_logging(
        **BASE,
        access_log_settings={},
    )

    assert result is not None

    finding = build_api_gateway_access_logging_finding(
        result
    )

    assert finding.rule_id == "CS-AWS-APIGATEWAY-009"


def test_private_https_only_applies_to_http_vpc_links():
    assert (
        check_api_gateway_private_https(
            **BASE,
            protocol_type="HTTP",
            connection_type="INTERNET",
            tls_config={},
        )
        is None
    )

    assert (
        check_api_gateway_private_https(
            **BASE,
            protocol_type="WEBSOCKET",
            connection_type="VPC_LINK",
            tls_config={},
        )
        is None
    )

    result = check_api_gateway_private_https(
        **BASE,
        protocol_type="HTTP",
        connection_type="VPC_LINK",
        tls_config={},
    )

    assert result is not None

    finding = build_api_gateway_private_https_finding(result)

    assert finding.rule_id == "CS-AWS-APIGATEWAY-010"


def test_private_https_with_tls():
    assert (
        check_api_gateway_private_https(
            **BASE,
            protocol_type="HTTP",
            connection_type="VPC_LINK",
            tls_config={
                "ServerNameToVerify": "internal.example.com"
            },
        )
        is None
    )


def test_domain_security_policy():
    assert (
        check_api_gateway_domain_security_policy(
            **BASE,
            security_policy=(
                "SecurityPolicy_TLS13_1_3_2025_09"
            ),
        )
        is None
    )

    result = check_api_gateway_domain_security_policy(
        **BASE,
        security_policy="TLS_1_2",
    )

    assert result is not None

    finding = (
        build_api_gateway_domain_security_policy_finding(
            result
        )
    )

    assert finding.rule_id == "CS-AWS-APIGATEWAY-011"
