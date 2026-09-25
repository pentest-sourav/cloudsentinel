from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.services.kinesis import KinesisService


def make_service():
    session = Mock()
    client = Mock()

    with patch(
        "scanner.aws.services.kinesis.create_aws_client",
        return_value=client,
    ):
        service = KinesisService(session)

    return service, client


def test_list_streams_returns_all_stream_names():
    service, client = make_service()

    client.list_streams.side_effect = [
        {
            "StreamNames": ["stream-a", "stream-b"],
            "HasMoreStreams": True,
            "NextToken": "token-1",
        },
        {
            "StreamNames": ["stream-c"],
            "HasMoreStreams": False,
        },
    ]

    result = service.list_streams()

    assert result == [
        "stream-a",
        "stream-b",
        "stream-c",
    ]

    assert client.list_streams.call_count == 2


def test_list_streams_wraps_client_error():
    service, client = make_service()

    client.list_streams.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "ListStreams",
    )

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: Access denied",
    ):
        service.list_streams()


def test_describe_stream_returns_summary():
    service, client = make_service()

    client.describe_stream_summary.return_value = {
        "StreamDescriptionSummary": {
            "StreamARN": (
                "arn:aws:kinesis:ap-south-1:"
                "123456789012:stream/orders"
            ),
            "EncryptionType": "KMS",
            "KeyId": "alias/aws/kinesis",
            "RetentionPeriodHours": 168,
            "StreamStatus": "ACTIVE",
        }
    }

    result = service.describe_stream("orders")

    client.describe_stream_summary.assert_called_once_with(
        StreamName="orders",
    )

    assert result["EncryptionType"] == "KMS"
    assert result["RetentionPeriodHours"] == 168


def test_describe_stream_wraps_sdk_error():
    service, client = make_service()

    client.describe_stream_summary.side_effect = (
        BotoCoreError()
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error",
    ):
        service.describe_stream("orders")


def test_list_stream_tags_returns_tags():
    service, client = make_service()

    client.list_tags_for_resource.return_value = {
        "Tags": [
            {
                "Key": "Environment",
                "Value": "production",
            }
        ]
    }

    result = service.list_stream_tags(
        "arn:aws:kinesis:ap-south-1:123456789012:stream/orders"
    )

    client.list_tags_for_resource.assert_called_once_with(
        ResourceARN=(
            "arn:aws:kinesis:ap-south-1:"
            "123456789012:stream/orders"
        ),
    )

    assert result == [
        {
            "Key": "Environment",
            "Value": "production",
        }
    ]


def test_list_stream_tags_wraps_client_error():
    service, client = make_service()

    client.list_tags_for_resource.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "ListTagsForResource",
    )

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: Access denied",
    ):
        service.list_stream_tags(
            "arn:aws:kinesis:ap-south-1:"
            "123456789012:stream/orders"
        )
