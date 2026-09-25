from unittest.mock import Mock

from scanner.aws.services.api_gateway import (
    APIGatewayService,
)


def make_service():
    session = Mock()
    session.region_name = "ap-south-1"

    service = object.__new__(APIGatewayService)

    service.session = session
    service.apigateway_client = Mock()
    service.apigatewayv2_client = Mock()
    service.wafv2_client = Mock()

    return service


def test_rest_api_has_http_integration():
    service = make_service()

    service.list_rest_resources = Mock(
        return_value=[
            {
                "id": "resource-1",
                "resourceMethods": {
                    "GET": {},
                },
            }
        ]
    )

    service.get_rest_integration = Mock(
        return_value={
            "type": "HTTP",
        }
    )

    assert (
        service.rest_api_has_http_integration("api-1")
        is True
    )


def test_rest_api_has_http_integration_returns_false():
    service = make_service()

    service.list_rest_resources = Mock(
        return_value=[
            {
                "id": "resource-1",
                "resourceMethods": {
                    "GET": {},
                },
            }
        ]
    )

    service.get_rest_integration = Mock(
        return_value={
            "type": "AWS_PROXY",
        }
    )

    assert (
        service.rest_api_has_http_integration("api-1")
        is False
    )
