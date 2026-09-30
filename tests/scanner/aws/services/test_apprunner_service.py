from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.apprunner import (
    AppRunnerService,
)


def make_service():
    session = Mock()
    session.region_name = "ap-south-1"

    client = Mock()

    service = AppRunnerService(session)
    service.apprunner_client = client

    return service, client


def test_list_services_collects_paginated_results():
    service, client = make_service()

    client.list_services.side_effect = [
        {
            "ServiceSummaryList": [
                {
                    "ServiceId": "11111111-1111-4111-8111-111111111111",
                    "ServiceArn": "arn:service:one",
                    "ServiceName": "frontend",
                    "Status": "RUNNING",
                }
            ],
            "NextToken": "token-1",
        },
        {
            "ServiceSummaryList": [
                {
                    "ServiceId": "22222222-2222-4222-8222-222222222222",
                    "ServiceArn": "arn:service:two",
                    "ServiceName": "backend",
                    "Status": "RUNNING",
                }
            ],
        },
    ]

    assert service.list_services() == [
        {
            "ServiceId": "11111111-1111-4111-8111-111111111111",
            "ServiceArn": "arn:service:one",
            "ServiceName": "frontend",
            "Status": "RUNNING",
        },
        {
            "ServiceId": "22222222-2222-4222-8222-222222222222",
            "ServiceArn": "arn:service:two",
            "ServiceName": "backend",
            "Status": "RUNNING",
        },
    ]

    assert client.list_services.call_args_list == [
        ((), {"MaxResults": 100}),
        ((), {"MaxResults": 100, "NextToken": "token-1"}),
    ]


def test_list_services_ignores_non_dict_entries():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "ServiceSummaryList": [
                {"ServiceId": "1111"},
                None,
                "invalid",
            ]
        }
    ]

    client.list_services.return_value = {
        "ServiceSummaryList": [
            {"ServiceId": "1111"},
            None,
            "invalid",
        ]
    }

    assert service.list_services() == [
        {"ServiceId": "1111"},
    ]


def test_list_vpc_connectors_collects_paginated_results():
    service, client = make_service()

    client.list_vpc_connectors.side_effect = [
        {
            "VpcConnectors": [
                {
                    "VpcConnectorArn": "arn:connector:one",
                    "VpcConnectorName": "frontend",
                    "VpcConnectorRevision": 1,
                    "Status": "ACTIVE",
                }
            ],
            "NextToken": "token-1",
        },
        {
            "VpcConnectors": [
                {
                    "VpcConnectorArn": "arn:connector:two",
                    "VpcConnectorName": "backend",
                    "VpcConnectorRevision": 1,
                    "Status": "ACTIVE",
                }
            ],
        },
    ]

    assert service.list_vpc_connectors() == [
        {
            "VpcConnectorArn": "arn:connector:one",
            "VpcConnectorName": "frontend",
            "VpcConnectorRevision": 1,
            "Status": "ACTIVE",
        },
        {
            "VpcConnectorArn": "arn:connector:two",
            "VpcConnectorName": "backend",
            "VpcConnectorRevision": 1,
            "Status": "ACTIVE",
        },
    ]

    assert client.list_vpc_connectors.call_args_list == [
        ((), {"MaxResults": 100}),
        ((), {"MaxResults": 100, "NextToken": "token-1"}),
    ]


def test_list_vpc_connectors_ignores_non_dict_entries():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "VpcConnectors": [
                {"VpcConnectorName": "frontend"},
                None,
                "invalid",
            ]
        }
    ]

    client.list_vpc_connectors.return_value = {
        "VpcConnectors": [
            {"VpcConnectorName": "frontend"},
            None,
            "invalid",
        ]
    }

    assert service.list_vpc_connectors() == [
        {"VpcConnectorName": "frontend"},
    ]


def test_list_tags_for_resource_returns_tag_list():
    service, client = make_service()

    client.list_tags_for_resource.return_value = {
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            },
            {
                "Key": "Owner",
                "Value": "security",
            },
        ]
    }

    assert service.list_tags_for_resource(
        "arn:resource"
    ) == [
        {
            "Key": "Environment",
            "Value": "prod",
        },
        {
            "Key": "Owner",
            "Value": "security",
        },
    ]

    client.list_tags_for_resource.assert_called_once_with(
        ResourceArn="arn:resource"
    )


def test_list_tags_for_resource_returns_empty_for_invalid_arn():
    service, client = make_service()

    assert service.list_tags_for_resource("") == []

    client.list_tags_for_resource.assert_not_called()


def test_list_services_normalizes_client_error():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "ListServices",
    )

    client.list_services.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.list_services()


def test_list_vpc_connectors_normalizes_client_error():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "ListVpcConnectors",
    )

    client.list_vpc_connectors.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.list_vpc_connectors()
