from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.ec2 import EC2Service


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = EC2Service(session)

    return service, client


def test_describe_addresses_uses_direct_api_call():
    service, client = make_service()

    client.describe_addresses.return_value = {
        "Addresses": [
            {
                "AllocationId": "eipalloc-001",
                "PublicIp": "1.2.3.4",
            },
            {
                "AllocationId": "eipalloc-002",
                "PublicIp": "5.6.7.8",
            },
        ]
    }

    result = service.describe_addresses()

    assert result == [
        {
            "AllocationId": "eipalloc-001",
            "PublicIp": "1.2.3.4",
        },
        {
            "AllocationId": "eipalloc-002",
            "PublicIp": "5.6.7.8",
        },
    ]

    client.describe_addresses.assert_called_once_with()
    client.get_paginator.assert_not_called()


def test_describe_addresses_ignores_non_dict_entries():
    service, client = make_service()

    client.describe_addresses.return_value = {
        "Addresses": [
            {"AllocationId": "eipalloc-001"},
            None,
            "invalid",
        ]
    }

    assert service.describe_addresses() == [
        {"AllocationId": "eipalloc-001"},
    ]


def test_describe_addresses_returns_empty_for_invalid_response():
    service, client = make_service()

    client.describe_addresses.return_value = {
        "Addresses": None,
    }

    assert service.describe_addresses() == []


def test_describe_addresses_normalizes_client_error():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            },
        },
        "DescribeAddresses",
    )

    client.describe_addresses.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.describe_addresses()
