from unittest.mock import Mock

from scanner.aws.collectors.firehose import FirehoseDataCollector


def test_collector_normalizes_encryption_configuration():
    service = Mock()
    service.list_delivery_streams.return_value = [
        "secure-stream"
    ]
    service.describe_delivery_stream.return_value = {
        "DeliveryStreamName": "secure-stream",
        "DeliveryStreamARN": (
            "arn:aws:firehose:region:123:"
            "deliverystream/secure-stream"
        ),
        "DeliveryStreamStatus": "ACTIVE",
        "DeliveryStreamType": "DirectPut",
        "DeliveryStreamEncryptionConfiguration": {
            "Status": "ENABLED",
            "KeyType": "CUSTOMER_MANAGED_CMK",
            "KeyARN": (
                "arn:aws:kms:region:123:key/example"
            ),
        },
    }

    collector = FirehoseDataCollector(service)

    result = collector.collect_delivery_streams()

    assert result == [
        {
            "delivery_stream_name": "secure-stream",
            "delivery_stream_arn": (
                "arn:aws:firehose:region:123:"
                "deliverystream/secure-stream"
            ),
            "delivery_stream_status": "ACTIVE",
            "delivery_stream_type": "DirectPut",
            "encryption_status": "ENABLED",
            "encryption_key_type": "CUSTOMER_MANAGED_CMK",
            "encryption_key_arn": (
                "arn:aws:kms:region:123:key/example"
            ),
        }
    ]


def test_collector_handles_missing_encryption_configuration():
    service = Mock()
    service.list_delivery_streams.return_value = [
        "legacy-stream"
    ]
    service.describe_delivery_stream.return_value = {
        "DeliveryStreamName": "legacy-stream",
        "DeliveryStreamStatus": "ACTIVE",
    }

    collector = FirehoseDataCollector(service)

    result = collector.collect_delivery_streams()

    assert result[0]["delivery_stream_name"] == "legacy-stream"
    assert result[0]["encryption_status"] is None


def test_collector_caches_streams():
    service = Mock()
    service.list_delivery_streams.return_value = [
        "stream-a"
    ]
    service.describe_delivery_stream.return_value = {
        "DeliveryStreamName": "stream-a",
        "DeliveryStreamEncryptionConfiguration": {
            "Status": "ENABLED",
        },
    }

    collector = FirehoseDataCollector(service)

    first = collector.collect_delivery_streams()
    second = collector.collect_delivery_streams()

    assert first == second
    service.list_delivery_streams.assert_called_once()
    service.describe_delivery_stream.assert_called_once_with(
        "stream-a"
    )
