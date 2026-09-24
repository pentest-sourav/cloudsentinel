from unittest.mock import Mock

from scanner.aws.collectors.sqs import SQSDataCollector


QUEUE_URL = "https://sqs.example/queue"
QUEUE_ARN = "arn:aws:sqs:region:account:queue"


def test_collect_queues_normalizes_security_data():
    service = Mock()

    service.list_queues.return_value = [QUEUE_URL]

    service.get_queue_attributes.return_value = {
        "QueueArn": QUEUE_ARN,
        "KmsMasterKeyId": "alias/aws/sqs",
        "SqsManagedSseEnabled": "false",
    }

    service.get_queue_policy.return_value = {
        "Statement": []
    }

    service.list_queue_tags.return_value = [
        {"Key": "Environment", "Value": "prod"}
    ]

    collector = SQSDataCollector(service)

    result = collector.collect_queues()

    assert result == [
        {
            "queue_url": QUEUE_URL,
            "queue_arn": QUEUE_ARN,
            "kms_master_key_id": "alias/aws/sqs",
            "sqs_managed_sse_enabled": "false",
            "policy": {"Statement": []},
            "tags": [
                {"Key": "Environment", "Value": "prod"}
            ],
        }
    ]


def test_collector_caches_queue_data():
    service = Mock()

    service.list_queues.return_value = [QUEUE_URL]

    service.get_queue_attributes.return_value = {
        "QueueArn": QUEUE_ARN,
        "KmsMasterKeyId": None,
        "SqsManagedSseEnabled": "true",
    }

    service.get_queue_policy.return_value = {}
    service.list_queue_tags.return_value = []

    collector = SQSDataCollector(service)

    collector.collect_queues()
    collector.collect_queues()

    service.list_queues.assert_called_once()
    service.get_queue_attributes.assert_called_once_with(
        QUEUE_URL
    )
    service.get_queue_policy.assert_called_once_with(
        QUEUE_URL
    )
    service.list_queue_tags.assert_called_once_with(
        QUEUE_URL
    )
