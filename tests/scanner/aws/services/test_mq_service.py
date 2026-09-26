from unittest.mock import Mock

import pytest

from scanner.aws.services.mq import MQService


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = MQService(session)

    return service, client


def test_list_brokers_paginates():
    service, client = make_service()

    client.list_brokers.side_effect = [
        {
            "BrokerSummaries": [
                {"BrokerId": "b-1"},
            ],
            "NextToken": "next",
        },
        {
            "BrokerSummaries": [
                {"BrokerId": "b-2"},
            ],
        },
    ]

    assert service.list_brokers() == [
        {"BrokerId": "b-1"},
        {"BrokerId": "b-2"},
    ]

    assert client.list_brokers.call_count == 2
    assert (
        client.list_brokers.call_args_list[1]
        .kwargs["NextToken"]
        == "next"
    )


def test_describe_broker():
    service, client = make_service()

    client.describe_broker.return_value = {
        "BrokerId": "b-1",
        "EngineType": "ACTIVEMQ",
    }

    assert service.describe_broker("b-1") == {
        "BrokerId": "b-1",
        "EngineType": "ACTIVEMQ",
    }

    client.describe_broker.assert_called_once_with(
        BrokerId="b-1",
    )


def test_list_broker_details_discovers_and_describes():
    service, client = make_service()

    client.list_brokers.return_value = {
        "BrokerSummaries": [
            {"BrokerId": "b-1"},
            {"BrokerId": "b-2"},
        ],
    }

    client.describe_broker.side_effect = [
        {"BrokerId": "b-1"},
        {"BrokerId": "b-2"},
    ]

    assert service.list_broker_details() == [
        {"BrokerId": "b-1"},
        {"BrokerId": "b-2"},
    ]


def test_service_wraps_client_error():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.list_brokers.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListBrokers",
    )

    with pytest.raises(
        RuntimeError,
        match="AWS Amazon MQ broker discovery failed",
    ):
        service.list_brokers()


def test_describe_broker_rejects_empty_id():
    service, _ = make_service()

    with pytest.raises(
        ValueError,
        match="broker ID must be a non-empty string",
    ):
        service.describe_broker("")
