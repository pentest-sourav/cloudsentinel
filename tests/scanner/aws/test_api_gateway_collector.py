from unittest.mock import Mock

from scanner.aws.collectors.api_gateway import (
    APIGatewayDataCollector,
)


def make_service():
    service = Mock()
    service.session.region_name = "ap-south-1"

    return service


def test_collect_rest_stages():
    service = make_service()

    service.list_rest_apis.return_value = [
        {
            "id": "api-1",
            "name": "orders",
        }
    ]

    service.rest_api_has_http_integration.return_value = True

    service.list_rest_stages.return_value = [
        {
            "stageName": "prod",
            "methodSettings": {
                "/*/*": {
                    "loggingLevel": "INFO",
                    "cachingEnabled": True,
                    "cacheDataEncrypted": True,
                }
            },
            "clientCertificateId": "cert-1",
            "tracingEnabled": True,
            "cacheClusterEnabled": True,
        }
    ]

    service.get_rest_stage_waf.return_value = {
        "ARN": "arn:aws:wafv2:test",
        "Name": "api-waf",
    }

    collector = APIGatewayDataCollector(service)

    stages = collector.collect_rest_stages()

    assert len(stages) == 1

    stage = stages[0]

    assert stage["rest_api_id"] == "api-1"
    assert stage["stage_name"] == "prod"
    assert stage["client_certificate_id"] == "cert-1"
    assert stage["tracing_enabled"] is True
    assert stage["waf_arn"] == "arn:aws:wafv2:test"


def test_collect_v2_routes():
    service = make_service()

    service.list_v2_apis.return_value = [
        {
            "ApiId": "api-1",
            "Name": "orders",
            "ProtocolType": "HTTP",
        }
    ]

    service.list_v2_routes.return_value = [
        {
            "RouteId": "route-1",
            "RouteKey": "GET /orders",
            "AuthorizationType": "JWT",
        }
    ]

    collector = APIGatewayDataCollector(service)

    routes = collector.collect_v2_routes()

    assert len(routes) == 1
    assert routes[0]["authorization_type"] == "JWT"


def test_collect_v2_private_integration():
    service = make_service()

    service.list_v2_apis.return_value = [
        {
            "ApiId": "api-1",
            "Name": "orders",
            "ProtocolType": "HTTP",
        }
    ]

    service.list_v2_integrations.return_value = [
        {
            "IntegrationId": "integration-1",
            "IntegrationType": "HTTP_PROXY",
            "ConnectionType": "VPC_LINK",
            "TlsConfig": {
                "ServerNameToVerify": "internal.example.com"
            },
        }
    ]

    collector = APIGatewayDataCollector(service)

    integrations = collector.collect_v2_integrations()

    assert len(integrations) == 1
    assert integrations[0]["connection_type"] == "VPC_LINK"
    assert integrations[0]["tls_config"]


def test_collect_v2_stage_access_logs():
    service = make_service()

    service.list_v2_apis.return_value = [
        {
            "ApiId": "api-1",
            "Name": "orders",
            "ProtocolType": "HTTP",
        }
    ]

    service.list_v2_stages.return_value = [
        {
            "StageName": "$default",
            "AccessLogSettings": {
                "DestinationArn": (
                    "arn:aws:logs:ap-south-1:123:"
                    "log-group:/aws/api"
                ),
                "Format": "$context.requestId",
            },
        }
    ]

    collector = APIGatewayDataCollector(service)

    stages = collector.collect_v2_stages()

    assert len(stages) == 1
    assert stages[0]["access_log_settings"][
        "DestinationArn"
    ].startswith("arn:aws:logs:")
