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


def test_cloudtrail_service_lists_event_data_stores_and_fetches_details():
    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    event_data_store_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:eventdatastore/"
        "11111111-2222-3333-4444-555555555555"
    )

    fake_cloudtrail.list_event_data_stores.return_value = {
        "EventDataStores": [
            {
                "EventDataStoreArn": event_data_store_arn,
                "Name": "security-events",
                "Status": "ENABLED",
            }
        ]
    }

    fake_cloudtrail.get_event_data_store.return_value = {
        "EventDataStoreArn": event_data_store_arn,
        "Name": "security-events",
        "Status": "ENABLED",
        "KmsKeyId": (
            "arn:aws:kms:eu-north-1:"
            "123456789012:key/"
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        ),
    }

    service = CloudTrailService(fake_session)

    result = service.list_event_data_stores()

    assert result == [
        {
            "EventDataStoreArn": event_data_store_arn,
            "Name": "security-events",
            "Status": "ENABLED",
            "KmsKeyId": (
                "arn:aws:kms:eu-north-1:"
                "123456789012:key/"
                "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            ),
        }
    ]

    fake_cloudtrail.list_event_data_stores.assert_called_once_with(
        MaxResults=50,
    )
    fake_cloudtrail.get_event_data_store.assert_called_once_with(
        EventDataStore=event_data_store_arn,
    )


def test_cloudtrail_service_paginates_event_data_stores():
    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    first_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:eventdatastore/first"
    )
    second_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:eventdatastore/second"
    )

    fake_cloudtrail.list_event_data_stores.side_effect = [
        {
            "EventDataStores": [
                {
                    "EventDataStoreArn": first_arn,
                }
            ],
            "NextToken": "next-page",
        },
        {
            "EventDataStores": [
                {
                    "EventDataStoreArn": second_arn,
                }
            ],
        },
    ]

    fake_cloudtrail.get_event_data_store.side_effect = [
        {
            "EventDataStoreArn": first_arn,
            "Name": "first",
            "KmsKeyId": "arn:aws:kms:eu-north-1:123456789012:key/first",
        },
        {
            "EventDataStoreArn": second_arn,
            "Name": "second",
            "KmsKeyId": None,
        },
    ]

    service = CloudTrailService(fake_session)

    result = service.list_event_data_stores()

    assert [item["Name"] for item in result] == [
        "first",
        "second",
    ]

    assert fake_cloudtrail.list_event_data_stores.call_count == 2

    first_call = fake_cloudtrail.list_event_data_stores.call_args_list[0]
    second_call = fake_cloudtrail.list_event_data_stores.call_args_list[1]

    assert first_call.kwargs == {
        "MaxResults": 50,
    }
    assert second_call.kwargs == {
        "MaxResults": 50,
        "NextToken": "next-page",
    }

    assert fake_cloudtrail.get_event_data_store.call_count == 2


def test_cloudtrail_service_gets_event_data_store_details():
    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    event_data_store_arn = (
        "arn:aws:cloudtrail:eu-north-1:"
        "123456789012:eventdatastore/"
        "11111111-2222-3333-4444-555555555555"
    )

    expected = {
        "EventDataStoreArn": event_data_store_arn,
        "Name": "security-events",
        "Status": "ENABLED",
        "KmsKeyId": None,
    }

    fake_cloudtrail.get_event_data_store.return_value = expected

    service = CloudTrailService(fake_session)

    result = service.get_event_data_store(event_data_store_arn)

    assert result == expected

    fake_cloudtrail.get_event_data_store.assert_called_once_with(
        EventDataStore=event_data_store_arn,
    )


def test_cloudtrail_service_get_event_data_store_handles_client_error():
    from botocore.exceptions import ClientError

    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    fake_cloudtrail.get_event_data_store.side_effect = ClientError(
        {
            "Error": {
                "Code": "ResourceNotFoundException",
                "Message": "Event data store not found",
            }
        },
        "GetEventDataStore",
    )

    service = CloudTrailService(fake_session)

    try:
        service.get_event_data_store("missing")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == (
            "CloudTrail event data store discovery failed: "
            "ResourceNotFoundException: Event data store not found"
        )


def test_cloudtrail_service_get_event_data_store_handles_sdk_error():
    from botocore.exceptions import BotoCoreError

    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    fake_cloudtrail.get_event_data_store.side_effect = BotoCoreError()

    service = CloudTrailService(fake_session)

    try:
        service.get_event_data_store("arn:test")
        assert False, "Expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc).startswith(
            "AWS SDK error during CloudTrail event data store discovery:"
        )


def test_cloudtrail_service_skips_event_data_stores_without_arn():
    fake_session = Mock(spec=boto3.Session)
    fake_cloudtrail = Mock()
    fake_session.client.return_value = fake_cloudtrail

    fake_cloudtrail.list_event_data_stores.return_value = {
        "EventDataStores": [
            {
                "Name": "invalid-store",
            }
        ]
    }

    service = CloudTrailService(fake_session)

    result = service.list_event_data_stores()

    assert result == []
    fake_cloudtrail.get_event_data_store.assert_not_called()
