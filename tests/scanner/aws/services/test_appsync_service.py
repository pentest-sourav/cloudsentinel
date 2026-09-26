from unittest.mock import Mock

import pytest

from scanner.aws.services.appsync import (
    AppSyncService,
)


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = AppSyncService(session)

    return service, client


def test_list_graphql_apis_paginates():
    service, client = make_service()

    client.get_paginator.return_value.paginate.return_value = [
        {
            "graphqlApis": [
                {
                    "apiId": "api-1",
                },
            ],
        },
        {
            "graphqlApis": [
                {
                    "apiId": "api-2",
                },
            ],
        },
    ]

    assert service.list_graphql_apis() == [
        {"apiId": "api-1"},
        {"apiId": "api-2"},
    ]

    client.get_paginator.assert_called_once_with(
        "list_graphql_apis",
    )


def test_list_graphql_apis_filters_invalid_entries():
    service, client = make_service()

    client.get_paginator.return_value.paginate.return_value = [
        {
            "graphqlApis": [
                {"apiId": "api-1"},
                None,
                "invalid",
            ],
        },
    ]

    assert service.list_graphql_apis() == [
        {"apiId": "api-1"},
    ]


def test_service_wraps_client_error():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.get_paginator.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            },
        },
        "ListGraphqlApis",
    )

    with pytest.raises(
        RuntimeError,
        match="AWS AppSync GraphQL API discovery failed",
    ):
        service.list_graphql_apis()
