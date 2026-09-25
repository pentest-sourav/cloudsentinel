from unittest.mock import Mock

from scanner.aws.collectors.api_gateway import APIGatewayDataCollector


def make_service():
    service = Mock()
    service.list_rest_apis.return_value = []
    service.list_rest_stages.return_value = []
    service.list_rest_resources.return_value = []
    service.list_v2_apis.return_value = []
    service.list_v2_stages.return_value = []
    service.list_v2_routes.return_value = []
    service.list_v2_integrations.return_value = []
    service.list_rest_domain_names.return_value = []
    service.list_v2_domain_names.return_value = []
    service.get_rest_stage_waf.return_value = {}
    service.rest_api_has_http_integration.return_value = False
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
                }
            },
        }
    ]

    service.get_rest_stage_waf.return_value = {
        "Name": "orders-waf"
    }

    collector = APIGatewayDataCollector(service)

    stages = collector.collect_rest_stages()

    assert len(stages) == 1
    assert stages[0]["rest_api_id"] == "api-1"
    assert stages[0]["api_name"] == "orders"
    assert stages[0]["stage_name"] == "prod"
    assert stages[0]["method_settings"]["/*/*"]["loggingLevel"] == "INFO"
    assert stages[0]["has_http_integration"] is True
    assert stages[0]["waf_name"] == "orders-waf"


def test_collect_execution_stages_includes_rest_and_websocket():
    service = make_service()

    service.list_rest_apis.return_value = [
        {
            "id": "rest-api-1",
            "name": "orders",
        }
    ]

    service.rest_api_has_http_integration.return_value = False

    service.list_rest_stages.return_value = [
        {
            "stageName": "prod",
            "methodSettings": {
                "/*/*": {
                    "loggingLevel": "ERROR",
                }
            },
        }
    ]

    service.list_v2_apis.return_value = [
        {
            "ApiId": "ws-api-1",
            "Name": "events",
            "ProtocolType": "WEBSOCKET",
        }
    ]

    service.list_v2_stages.return_value = [
        {
            "StageName": "prod",
            "DefaultRouteSettings": {
                "LoggingLevel": "INFO",
            },
        }
    ]

    collector = APIGatewayDataCollector(service)

    stages = collector.collect_execution_stages()

    assert len(stages) == 2

    rest_stage = next(
        stage for stage in stages if stage["api_protocol_type"] == "REST"
    )
    websocket_stage = next(
        stage for stage in stages if stage["api_protocol_type"] == "WEBSOCKET"
    )

    assert rest_stage["logging_level"] == "ERROR"
    assert websocket_stage["logging_level"] == "INFO"


def test_collect_execution_stages_websocket_route_logging():
    service = make_service()

    service.list_v2_apis.return_value = [
        {
            "ApiId": "ws-api-1",
            "Name": "events",
            "ProtocolType": "WEBSOCKET",
        }
    ]

    service.list_v2_stages.return_value = [
        {
            "StageName": "prod",
            "DefaultRouteSettings": {},
        }
    ]

    service.list_v2_routes.return_value = [
        {
            "RouteKey": "$connect",
        },
        {
            "RouteKey": "orders",
        },
    ]

    collector = APIGatewayDataCollector(service)

    stages = collector.collect_execution_stages()

    assert len(stages) == 1
    assert stages[0]["api_protocol_type"] == "WEBSOCKET"
    assert stages[0]["logging_level"] is None


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
            "AuthorizationType": "AWS_IAM",
        }
    ]

    collector = APIGatewayDataCollector(service)

    routes = collector.collect_v2_routes()

    assert len(routes) == 1
    assert routes[0]["api_id"] == "api-1"
    assert routes[0]["api_name"] == "orders"
    assert routes[0]["route_id"] == "route-1"
    assert routes[0]["route_key"] == "GET /orders"
    assert routes[0]["authorization_type"] == "AWS_IAM"


def test_collect_v2_integrations_private_https():
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
            "IntegrationUri": "http://internal.example.com",
            "ConnectionType": "VPC_LINK",
            "TlsConfig": {
                "ServerNameToVerify": "internal.example.com",
            },
        }
    ]

    collector = APIGatewayDataCollector(service)

    integrations = collector.collect_v2_integrations()

    assert len(integrations) == 1
    assert integrations[0]["api_id"] == "api-1"
    assert integrations[0]["integration_id"] == "integration-1"
    assert integrations[0]["integration_type"] == "HTTP_PROXY"
    assert integrations[0]["connection_type"] == "VPC_LINK"
    assert integrations[0]["tls_config"] == {
        "ServerNameToVerify": "internal.example.com"
    }


def test_collect_v2_stages_access_logging():
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
            "StageName": "prod",
            "AccessLogSettings": {
                "DestinationArn": "arn:aws:logs:region:account:log-group:test",
                "Format": "$context.requestId",
            },
        }
    ]

    collector = APIGatewayDataCollector(service)

    stages = collector.collect_v2_stages()

    assert len(stages) == 1
    assert stages[0]["api_id"] == "api-1"
    assert stages[0]["api_name"] == "orders"
    assert stages[0]["stage_name"] == "prod"
    assert stages[0]["access_log_settings"] == {
        "DestinationArn": "arn:aws:logs:region:account:log-group:test",
        "Format": "$context.requestId",
    }


def test_rest_logging_level_fails_when_any_method_setting_lacks_logging():
    service = make_service()

    service.list_rest_apis.return_value = [
        {
            "id": "api-1",
            "name": "orders",
        }
    ]

    service.rest_api_has_http_integration.return_value = False
    service.list_v2_apis.return_value = []

    service.list_rest_stages.return_value = [
        {
            "stageName": "prod",
            "methodSettings": {
                "/*/*": {
                    "loggingLevel": "ERROR",
                },
                "GET /orders": {
                    "metricsEnabled": True,
                },
            },
        }
    ]

    service.get_rest_stage_waf.return_value = {}

    collector = APIGatewayDataCollector(service)

    stages = collector.collect_execution_stages()

    assert len(stages) == 1
    assert stages[0]["logging_level"] == "OFF"


def test_collect_domains_only_includes_rest_api_gateway_domains():
    service = make_service()

    service.list_rest_domain_names.return_value = [
        {
            "domainName": "api.example.com",
            "securityPolicy": "TLS_1_2",
        }
    ]

    service.list_v2_domain_names.return_value = [
        {
            "DomainName": "http-api.example.com",
            "SecurityPolicy": "TLS_1_2",
        }
    ]

    collector = APIGatewayDataCollector(service)

    domains = collector.collect_domains()

    assert len(domains) == 1
    assert domains[0]["domain_name"] == "api.example.com"
    assert domains[0]["security_policy"] == "TLS_1_2"
