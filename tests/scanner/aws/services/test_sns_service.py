from unittest.mock import Mock

import boto3
from botocore.exceptions import ClientError

from scanner.aws.services.sns import SNSService
from scanner.aws.session import AWS_RETRY_CONFIG


def test_list_topics():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.list_topics.return_value = {
        "Topics": [
            {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic-one"},
            {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic-two"},
        ]
    }

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    topics = service.list_topics()

    assert topics == [
        {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic-one"},
        {"TopicArn": "arn:aws:sns:us-east-1:123456789012:topic-two"},
    ]

    fake_sns.list_topics.assert_called_once_with()


def test_list_topics_handles_invalid_response():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.list_topics.return_value = {
        "Topics": [
            {"TopicArn": "arn:aws:sns:us-east-1:123456789012:valid-topic"},
            {"Invalid": "topic"},
            "invalid",
            {},
        ]
    }

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    topics = service.list_topics()

    assert topics == [
        {"TopicArn": "arn:aws:sns:us-east-1:123456789012:valid-topic"}
    ]


def test_list_topics_returns_empty_when_topics_are_missing():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.list_topics.return_value = {}

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    assert service.list_topics() == []


def test_list_topics_handles_client_error():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.list_topics.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListTopics",
    )

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    try:
        service.list_topics()
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "SNS topic discovery failed" in str(exc)
        assert "AccessDenied" in str(exc)


def test_get_topic_attributes():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.get_topic_attributes.return_value = {
        "Attributes": {
            "TopicArn": "arn:aws:sns:us-east-1:123456789012:topic",
            "KmsMasterKeyId": "alias/aws/sns",
            "DisplayName": "cloudsentinel",
        }
    }

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    attributes = service.get_topic_attributes(
        "arn:aws:sns:us-east-1:123456789012:topic"
    )

    assert attributes == {
        "TopicArn": "arn:aws:sns:us-east-1:123456789012:topic",
        "KmsMasterKeyId": "alias/aws/sns",
        "DisplayName": "cloudsentinel",
    }

    fake_sns.get_topic_attributes.assert_called_once_with(
        TopicArn="arn:aws:sns:us-east-1:123456789012:topic"
    )


def test_get_topic_attributes_handles_client_error():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.get_topic_attributes.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "GetTopicAttributes",
    )

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    try:
        service.get_topic_attributes(
            "arn:aws:sns:us-east-1:123456789012:topic"
        )
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "SNS topic attributes discovery failed" in str(exc)
        assert "AccessDenied" in str(exc)


def test_get_topic_policy():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.get_topic_attributes.return_value = {
        "Attributes": {
            "Policy": '{"Version":"2012-10-17","Statement":[]}'
        }
    }

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    policy = service.get_topic_policy(
        "arn:aws:sns:us-east-1:123456789012:topic"
    )

    assert policy == {
        "Version": "2012-10-17",
        "Statement": [],
    }

    fake_sns.get_topic_attributes.assert_called_once_with(
        TopicArn="arn:aws:sns:us-east-1:123456789012:topic",
        AttributeNames=["Policy"],
    )


def test_list_tags():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.list_tags_for_resource.return_value = {
        "Tags": [
            {"Key": "Environment", "Value": "production"},
            {"Key": "Owner", "Value": "security"},
        ]
    }

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    tags = service.list_tags(
        "arn:aws:sns:us-east-1:123456789012:topic"
    )

    assert tags == [
        {"Key": "Environment", "Value": "production"},
        {"Key": "Owner", "Value": "security"},
    ]

    fake_sns.list_tags_for_resource.assert_called_once_with(
        ResourceArn="arn:aws:sns:us-east-1:123456789012:topic"
    )


def test_list_tags_filters_invalid_tags():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.list_tags_for_resource.return_value = {
        "Tags": [
            {"Key": "Environment", "Value": "production"},
            "invalid",
            {},
            {"Key": "Owner", "Value": "security"},
        ]
    }

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    tags = service.list_tags(
        "arn:aws:sns:us-east-1:123456789012:topic"
    )

    assert tags == [
        {"Key": "Environment", "Value": "production"},
        {},
        {"Key": "Owner", "Value": "security"},
    ]


def test_list_tags_handles_client_error():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.list_tags_for_resource.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListTagsForResource",
    )

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    try:
        service.list_tags(
            "arn:aws:sns:us-east-1:123456789012:topic"
        )
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert "SNS topic tag discovery failed" in str(exc)
        assert "AccessDenied" in str(exc)


def test_sns_service_uses_centralized_retry_config():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    assert service.sns_client is fake_sns

    fake_session.client.assert_called_once_with(
        "sns",
        region_name="us-east-1",
        config=AWS_RETRY_CONFIG,
    )


def test_list_topics_handles_pagination():
    fake_session = Mock(spec=boto3.Session)
    fake_sns = Mock()

    fake_sns.list_topics.side_effect = [
        {
            "Topics": [
                {
                    "TopicArn": (
                        "arn:aws:sns:us-east-1:"
                        "123456789012:topic-one"
                    )
                }
            ],
            "NextToken": "page-two",
        },
        {
            "Topics": [
                {
                    "TopicArn": (
                        "arn:aws:sns:us-east-1:"
                        "123456789012:topic-two"
                    )
                }
            ]
        },
    ]

    fake_session.client.return_value = fake_sns

    service = SNSService(fake_session, "us-east-1")

    topics = service.list_topics()

    assert topics == [
        {
            "TopicArn": (
                "arn:aws:sns:us-east-1:"
                "123456789012:topic-one"
            )
        },
        {
            "TopicArn": (
                "arn:aws:sns:us-east-1:"
                "123456789012:topic-two"
            )
        },
    ]

    assert fake_sns.list_topics.call_count == 2
    assert fake_sns.list_topics.call_args_list[0].kwargs == {}
    assert fake_sns.list_topics.call_args_list[1].kwargs == {
        "NextToken": "page-two",
    }
