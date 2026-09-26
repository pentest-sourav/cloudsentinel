from unittest.mock import Mock

from scanner.aws.services.firehose import FirehoseService


def test_list_delivery_streams_uses_pagination():
    session = Mock()
    client = Mock()
    paginator = Mock()

    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {
            "DeliveryStreamNames": [
                "stream-a",
                "stream-b",
            ]
        },
        {
            "DeliveryStreamNames": [
                "stream-c",
            ]
        },
    ]
    session.client.return_value = client

    service = FirehoseService(session)

    assert service.list_delivery_streams() == [
        "stream-a",
        "stream-b",
        "stream-c",
    ]

    client.get_paginator.assert_called_once_with(
        "list_delivery_streams"
    )


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
