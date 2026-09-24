from unittest.mock import Mock

from scanner.aws.scanners.sns import SNSScanner


def test_sns_scanner_executes_sns_rules():
    service = Mock()

    service.list_topics.return_value = [
        {
            "TopicArn": (
                "arn:aws:sns:ap-south-1:"
                "123456789012:cloudsentinel"
            )
        }
    ]

    service.get_topic_attributes.return_value = {
        "KmsMasterKeyId": "alias/aws/sns",
        "HTTPSuccessFeedbackRoleArn": (
            "arn:aws:iam::123456789012:role/sns-feedback"
        ),
    }

    service.get_topic_policy.return_value = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:root"
                },
                "Action": "sns:Publish",
            }
        ]
    }

    service.list_tags.return_value = [
        {
            "Key": "Environment",
            "Value": "test",
        }
    ]

    scanner = SNSScanner(service)

    findings = scanner.scan()

    assert findings == []
