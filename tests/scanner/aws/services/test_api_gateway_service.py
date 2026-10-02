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


def test_get_rest_stage_waf_treats_missing_waf_as_empty():
    from botocore.exceptions import ClientError

    service = make_service()

    service.wafv2_client.get_web_acl_for_resource.side_effect = (
        ClientError(
            {
                "Error": {
                    "Code": "WAFNonexistentItemException",
                    "Message": "No web ACL is associated",
                }
            },
            "GetWebACLForResource",
        )
    )

    assert (
        service.get_rest_stage_waf(
            rest_api_id="api-1",
            stage_name="prod",
        )
        == {}
    )


def test_list_v2_stages_handles_multiple_pages():
    service = make_service()

    service.apigatewayv2_client.get_stages.side_effect = [
        {
            "Items": [
                {
                    "StageName": "dev",
                },
                {
                    "StageName": "staging",
                },
            ],
            "NextToken": "page-2",
        },
        {
            "Items": [
                {
                    "StageName": "prod",
                },
            ],
        },
    ]

    stages = service.list_v2_stages("api-1")

    assert stages == [
        {"StageName": "dev"},
        {"StageName": "staging"},
        {"StageName": "prod"},
    ]

    assert service.apigatewayv2_client.get_stages.call_count == 2

    service.apigatewayv2_client.get_stages.assert_any_call(
        ApiId="api-1",
        MaxResults="100",
    )

    service.apigatewayv2_client.get_stages.assert_any_call(
        ApiId="api-1",
        MaxResults="100",
        NextToken="page-2",
    )


def test_list_v2_stages_returns_empty_when_items_is_not_a_list():
    service = make_service()

    service.apigatewayv2_client.get_stages.return_value = {
        "Items": None,
    }

    assert service.list_v2_stages("api-1") == []

    service.apigatewayv2_client.get_stages.assert_called_once_with(
        ApiId="api-1",
        MaxResults="100",
    )
