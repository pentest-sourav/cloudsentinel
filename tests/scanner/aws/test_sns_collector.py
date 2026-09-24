from unittest.mock import Mock

from scanner.aws.collectors.sns import SNSDataCollector


TOPIC_ONE = "arn:aws:sns:us-east-1:123456789012:topic-one"
TOPIC_TWO = "arn:aws:sns:us-east-1:123456789012:topic-two"


def test_collect_topics():
    service = Mock()

    service.list_topics.return_value = [
        {"TopicArn": TOPIC_ONE},
        {"TopicArn": TOPIC_TWO},
    ]

    collector = SNSDataCollector(service)

    assert collector.collect_topics() == [
        {"topic_arn": TOPIC_ONE},
        {"topic_arn": TOPIC_TWO},
    ]

    service.list_topics.assert_called_once_with()


def test_collect_topics_ignores_invalid_topics():
    service = Mock()

    service.list_topics.return_value = [
        {"TopicArn": TOPIC_ONE},
        {"Invalid": "topic"},
        {},
    ]

    collector = SNSDataCollector(service)

    assert collector.collect_topics() == [
        {"topic_arn": TOPIC_ONE},
    ]


def test_collect_topics_caches_topic_discovery():
    service = Mock()

    service.list_topics.return_value = [
        {"TopicArn": TOPIC_ONE},
    ]

    collector = SNSDataCollector(service)

    collector.collect_topics()
    collector.collect_topics()

    service.list_topics.assert_called_once_with()


def test_collect_security():
    service = Mock()

    service.list_topics.return_value = [
        {"TopicArn": TOPIC_ONE},
        {"TopicArn": TOPIC_TWO},
    ]

    service.get_topic_attributes.side_effect = [
        {
            "TopicArn": TOPIC_ONE,
            "KmsMasterKeyId": "alias/aws/sns",
        },
        {
            "TopicArn": TOPIC_TWO,
        },
    ]

    service.get_topic_policy.side_effect = [
        {"Statement": []},
        {"Statement": [{"Effect": "Allow"}]},
    ]

    service.list_tags.side_effect = [
        [{"Key": "Environment", "Value": "production"}],
        [],
    ]

    collector = SNSDataCollector(service)

    result = collector.collect_security()

    assert result == [
        {
            "topic_arn": TOPIC_ONE,
            "attributes": {
                "TopicArn": TOPIC_ONE,
                "KmsMasterKeyId": "alias/aws/sns",
            },
            "policy": {"Statement": []},
            "tags": [
                {"Key": "Environment", "Value": "production"}
            ],
        },
        {
            "topic_arn": TOPIC_TWO,
            "attributes": {
                "TopicArn": TOPIC_TWO,
            },
            "policy": {
                "Statement": [
                    {"Effect": "Allow"}
                ]
            },
            "tags": [],
        },
    ]

    assert service.get_topic_attributes.call_count == 2
    assert service.get_topic_policy.call_count == 2
    assert service.list_tags.call_count == 2


def test_collect_security_caches_topic_data():
    service = Mock()

    service.list_topics.return_value = [
        {"TopicArn": TOPIC_ONE},
    ]

    service.get_topic_attributes.return_value = {
        "TopicArn": TOPIC_ONE,
    }

    service.get_topic_policy.return_value = {
        "Statement": [],
    }

    service.list_tags.return_value = []

    collector = SNSDataCollector(service)

    collector.collect_security()
    collector.collect_security()

    service.list_topics.assert_called_once_with()
    service.get_topic_attributes.assert_called_once_with(TOPIC_ONE)
    service.get_topic_policy.assert_called_once_with(TOPIC_ONE)
    service.list_tags.assert_called_once_with(TOPIC_ONE)


def test_collect_security_ignores_invalid_topics():
    service = Mock()

    service.list_topics.return_value = [
        {"TopicArn": TOPIC_ONE},
        {},
        {"Invalid": "topic"},
    ]

    service.get_topic_attributes.return_value = {
        "TopicArn": TOPIC_ONE,
    }
    service.get_topic_policy.return_value = {}
    service.list_tags.return_value = []

    collector = SNSDataCollector(service)

    result = collector.collect_security()

    assert result == [
        {
            "topic_arn": TOPIC_ONE,
            "attributes": {
                "TopicArn": TOPIC_ONE,
            },
            "policy": {},
            "tags": [],
        }
    ]

    service.get_topic_attributes.assert_called_once_with(TOPIC_ONE)
    service.get_topic_policy.assert_called_once_with(TOPIC_ONE)
    service.list_tags.assert_called_once_with(TOPIC_ONE)
