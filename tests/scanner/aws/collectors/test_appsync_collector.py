from unittest.mock import Mock

from scanner.aws.collectors.appsync import (
    AppSyncDataCollector,
)


def test_collect_graphql_apis_normalizes_security_fields():
    service = Mock()

    service.list_graphql_apis.return_value = [
        {
            "apiId": "api-123",
            "arn": (
                "arn:aws:appsync:ap-south-1:"
                "123456789012:apis/api-123"
            ),
            "name": "production-api",
            "apiType": "GRAPHQL",
            "authenticationType": "AWS_IAM",
            "additionalAuthenticationProviders": [
                {
                    "authenticationType": (
                        "AMAZON_COGNITO_USER_POOLS"
                    ),
                },
            ],
            "logConfig": {
                "fieldLogLevel": "ALL",
            },
            "tags": {
                "Environment": "prod",
                "aws:cloudformation:stack-id": "system",
            },
        },
    ]

    collector = AppSyncDataCollector(service)

    assert collector.collect_graphql_apis() == [
        {
            "resource_id": "api-123",
            "resource_type": "appsync_graphql_api",
            "resource_arn": (
                "arn:aws:appsync:ap-south-1:"
                "123456789012:apis/api-123"
            ),
            "name": "production-api",
            "api_type": "GRAPHQL",
            "authentication_type": "AWS_IAM",
            "additional_authentication_types": [
                "AMAZON_COGNITO_USER_POOLS",
            ],
            "field_log_level": "ALL",
            "tags": {
                "Environment": "prod",
            },
            "has_non_system_tags": True,
        },
    ]


def test_collector_caches_graphql_apis():
    service = Mock()

    service.list_graphql_apis.return_value = [
        {
            "apiId": "api-123",
        },
    ]

    collector = AppSyncDataCollector(service)

    collector.collect_graphql_apis()
    collector.collect_graphql_apis()

    service.list_graphql_apis.assert_called_once()


def test_collector_ignores_system_tags():
    service = Mock()

    service.list_graphql_apis.return_value = [
        {
            "apiId": "api-123",
            "tags": {
                "aws:cloudformation:stack-id": "system",
            },
        },
    ]

    collector = AppSyncDataCollector(service)

    result = collector.collect_graphql_apis()[0]

    assert result["tags"] == {}
    assert result["has_non_system_tags"] is False


def test_collector_skips_api_without_id():
    service = Mock()

    service.list_graphql_apis.return_value = [
        {
            "name": "invalid-api",
        },
        {
            "apiId": "api-valid",
        },
    ]

    collector = AppSyncDataCollector(service)

    assert [
        item["resource_id"]
        for item in collector.collect_graphql_apis()
    ] == ["api-valid"]
