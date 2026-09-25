from unittest.mock import Mock

from scanner.aws.collectors.kinesis import KinesisDataCollector


STREAM_ARN = (
    "arn:aws:kinesis:ap-south-1:"
    "123456789012:stream/orders"
)


def test_collect_streams_normalizes_configuration():
    service = Mock()

    service.list_streams.return_value = ["orders"]

    service.describe_stream.return_value = {
        "StreamARN": STREAM_ARN,
        "EncryptionType": "KMS",
        "KeyId": "alias/aws/kinesis",
        "RetentionPeriodHours": 168,
        "StreamStatus": "ACTIVE",
    }

    service.list_stream_tags.return_value = [
        {
            "Key": "Environment",
            "Value": "production",
        }
    ]

    collector = KinesisDataCollector(service)

    result = collector.collect_streams()

    assert result == [
        {
            "stream_name": "orders",
            "stream_arn": STREAM_ARN,
            "encryption_type": "KMS",
            "key_id": "alias/aws/kinesis",
            "retention_period_hours": 168,
            "stream_status": "ACTIVE",
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "production",
                }
            ],
        }
    ]


def test_collect_streams_skips_stream_without_arn():
    service = Mock()

    service.list_streams.return_value = ["orders"]

    service.describe_stream.return_value = {
        "EncryptionType": "NONE",
        "RetentionPeriodHours": 24,
    }

    collector = KinesisDataCollector(service)

    assert collector.collect_streams() == []

    service.list_stream_tags.assert_not_called()


def test_collect_streams_caches_discovery_calls():
    service = Mock()

    service.list_streams.return_value = ["orders"]

    service.describe_stream.return_value = {
        "StreamARN": STREAM_ARN,
        "EncryptionType": "KMS",
        "RetentionPeriodHours": 168,
    }

    service.list_stream_tags.return_value = []

    collector = KinesisDataCollector(service)

    first = collector.collect_streams()
    second = collector.collect_streams()

    assert first == second

    service.list_streams.assert_called_once_with()
    service.describe_stream.assert_called_once_with(
        "orders"
    )
    service.list_stream_tags.assert_called_once_with(
        STREAM_ARN
    )
