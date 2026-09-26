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

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "ServiceSummaryList": [
                {
                    "ServiceId": "11111111-1111-4111-8111-111111111111",
                    "ServiceArn": "arn:service:one",
                    "ServiceName": "frontend",
                    "Status": "RUNNING",
                }
            ]
        },
        {
            "ServiceSummaryList": [
                {
                    "ServiceId": "22222222-2222-4222-8222-222222222222",
                    "ServiceArn": "arn:service:two",
                    "ServiceName": "backend",
                    "Status": "RUNNING",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

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

    client.get_paginator.assert_called_once_with(
        "list_services"
    )


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

    client.get_paginator.return_value = paginator

    assert service.list_services() == [
        {"ServiceId": "1111"},
    ]


def test_list_vpc_connectors_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "VpcConnectors": [
                {
                    "VpcConnectorArn": "arn:connector:one",
                    "VpcConnectorName": "frontend",
                    "VpcConnectorRevision": 1,
                    "Status": "ACTIVE",
                }
            ]
        },
        {
            "VpcConnectors": [
                {
                    "VpcConnectorArn": "arn:connector:two",
                    "VpcConnectorName": "backend",
                    "VpcConnectorRevision": 1,
                    "Status": "ACTIVE",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

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

    client.get_paginator.assert_called_once_with(
        "list_vpc_connectors"
    )


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

    client.get_paginator.return_value = paginator

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

    client.get_paginator.side_effect = error

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

    client.get_paginator.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.list_vpc_connectors()
