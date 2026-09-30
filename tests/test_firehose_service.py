from unittest.mock import Mock

from scanner.aws.services.firehose import FirehoseService


def test_list_delivery_streams_uses_pagination():
    session = Mock()
    client = Mock()

    client.list_delivery_streams.side_effect = [
        {
            "DeliveryStreamNames": [
                "stream-a",
                "stream-b",
            ],
            "HasMoreDeliveryStreams": True,
        },
        {
            "DeliveryStreamNames": [
                "stream-c",
            ],
            "HasMoreDeliveryStreams": False,
        },
    ]

    session.client.return_value = client

    service = FirehoseService(session)

    assert service.list_delivery_streams() == [
        "stream-a",
        "stream-b",
        "stream-c",
    ]

    assert client.list_delivery_streams.call_args_list[0].kwargs == {
        "Limit": 100,
    }

    assert client.list_delivery_streams.call_args_list[1].kwargs == {
        "Limit": 100,
        "ExclusiveStartDeliveryStreamName": "stream-b",
    }

    client.get_paginator.assert_not_called()


def test_describe_delivery_stream_returns_description():
    session = Mock()
    client = Mock()

    client.describe_delivery_stream.return_value = {
        "DeliveryStreamDescription": {
            "DeliveryStreamName": "secure-stream",
            "DeliveryStreamARN": (
                "arn:aws:firehose:region:123:"
                "deliverystream/secure-stream"
            ),
            "DeliveryStreamStatus": "ACTIVE",
            "DeliveryStreamEncryptionConfiguration": {
                "Status": "ENABLED",
                "KeyType": "AWS_OWNED_CMK",
            },
        }
    }
    session.client.return_value = client

    service = FirehoseService(session)

    result = service.describe_delivery_stream(
        "secure-stream"
    )

    assert result["DeliveryStreamName"] == "secure-stream"
    assert (
        result["DeliveryStreamEncryptionConfiguration"]["Status"]
        == "ENABLED"
    )

    client.describe_delivery_stream.assert_called_once_with(
        DeliveryStreamName="secure-stream"
    )


def test_empty_delivery_stream_name_returns_empty_result():
    session = Mock()
    service = FirehoseService(session)

    assert service.describe_delivery_stream("") == {}
