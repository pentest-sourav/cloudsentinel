from unittest.mock import Mock

from scanner.aws.services.sqs import SQSService


def test_list_queues_collects_all_pages():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.list_queues.side_effect = [
        {
            "QueueUrls": ["https://sqs.example/queue-a"],
            "NextToken": "next",
        },
        {
            "QueueUrls": ["https://sqs.example/queue-b"],
        },
    ]

    service = SQSService(session)

    assert service.list_queues() == [
        "https://sqs.example/queue-a",
        "https://sqs.example/queue-b",
    ]

    assert client.list_queues.call_count == 2


def test_get_queue_attributes_returns_attributes():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.get_queue_attributes.return_value = {
        "Attributes": {
            "QueueArn": "arn:aws:sqs:region:account:queue",
            "SqsManagedSseEnabled": "true",
        }
    }

    service = SQSService(session)

    result = service.get_queue_attributes(
        "https://sqs.example/queue"
    )

    assert result["QueueArn"].endswith(":queue")
    assert result["SqsManagedSseEnabled"] == "true"


def test_get_queue_policy_parses_json():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.get_queue_attributes.return_value = {
        "Attributes": {
            "Policy": (
                '{"Version":"2012-10-17",'
                '"Statement":[]}'
            )
        }
    }

    service = SQSService(session)

    result = service.get_queue_policy(
        "https://sqs.example/queue"
    )

    assert result == {
        "Version": "2012-10-17",
        "Statement": [],
    }


def test_list_queue_tags_normalizes_dict():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.list_queue_tags.return_value = {
        "Tags": {
            "Environment": "prod",
            "Owner": "security",
        }
    }

    service = SQSService(session)

    result = service.list_queue_tags(
        "https://sqs.example/queue"
    )

    assert result == [
        {"Key": "Environment", "Value": "prod"},
        {"Key": "Owner", "Value": "security"},
    ]
