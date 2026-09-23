from unittest.mock import Mock

import boto3

from scanner.aws.services.cloudtrail import CloudTrailService
from scanner.aws.session import AWS_RETRY_CONFIG


def test_cloudtrail_service_uses_centralized_retry_config():
    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    service = CloudTrailService(fake_session)

    assert service.cloudtrail_client is fake_cloudtrail
    fake_session.client.assert_called_once_with(
        "cloudtrail",
        config=AWS_RETRY_CONFIG,
    )


def test_cloudtrail_service_lists_trail_tags():
    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    fake_cloudtrail.list_tags.return_value = {
        "ResourceTagList": [
            {
                "ResourceId": (
                    "arn:aws:cloudtrail:eu-north-1:"
                    "123456789012:trail/cloudtrail-main"
                ),
                "TagsList": [
                    {
                        "Key": "Environment",
                        "Value": "Production",
                    }
                ],
            }
        ]
    }

    service = CloudTrailService(fake_session)

    trail_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:trail/cloudtrail-main"
    )

    result = service.list_trail_tags([trail_arn])

    assert result == {
        trail_arn: [
            {
                "Key": "Environment",
                "Value": "Production",
            }
        ]
    }

    fake_cloudtrail.list_tags.assert_called_once_with(
        ResourceIdList=[trail_arn],
    )


def test_cloudtrail_service_batches_trail_tag_requests():
    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    fake_cloudtrail.list_tags.side_effect = [
        {"ResourceTagList": []},
        {"ResourceTagList": []},
    ]

    service = CloudTrailService(fake_session)

    trail_arns = [
        f"arn:aws:cloudtrail:eu-north-1:123456789012:trail/trail-{index}"
        for index in range(21)
    ]

    result = service.list_trail_tags(trail_arns)

    assert result == {}
    assert fake_cloudtrail.list_tags.call_count == 2

    first_call = fake_cloudtrail.list_tags.call_args_list[0]
    second_call = fake_cloudtrail.list_tags.call_args_list[1]

    assert first_call.kwargs["ResourceIdList"] == trail_arns[:20]
    assert second_call.kwargs["ResourceIdList"] == trail_arns[20:]
