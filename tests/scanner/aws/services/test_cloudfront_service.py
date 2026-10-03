from unittest.mock import Mock

import pytest

from scanner.aws.services.cloudfront import (
    CloudFrontService,
)


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = CloudFrontService(session)

    return service, client


def test_list_distributions_paginates():
    service, client = make_service()

    client.list_distributions.side_effect = [
        {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "E1",
                    },
                ],
                "IsTruncated": True,
                "NextMarker": "next-marker",
            },
        },
        {
            "DistributionList": {
                "Items": [
                    {
                        "Id": "E2",
                    },
                ],
                "IsTruncated": False,
            },
        },
    ]

    assert service.list_distributions() == [
        {"Id": "E1"},
        {"Id": "E2"},
    ]

    assert client.list_distributions.call_count == 2

    assert (
        client.list_distributions.call_args_list[1]
        .kwargs["Marker"]
        == "next-marker"
    )


def test_list_distributions_handles_empty_response():
    service, client = make_service()

    client.list_distributions.return_value = {
        "DistributionList": {
            "Items": [],
            "IsTruncated": False,
        },
    }

    assert service.list_distributions() == []


def test_list_distributions_wraps_client_error():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.list_distributions.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListDistributions",
    )

    with pytest.raises(
        RuntimeError,
        match="AWS CloudFront distribution discovery failed",
    ):
        service.list_distributions()


def test_check_s3_bucket_exists_returns_true():
    service, client = make_service()

    assert service.check_s3_bucket_exists(
        "example-bucket"
    ) is True

    client.head_bucket.assert_called_once_with(
        Bucket="example-bucket"
    )


def test_check_s3_bucket_exists_returns_false_for_missing_bucket():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.head_bucket.side_effect = ClientError(
        {
            "Error": {
                "Code": "404",
            }
        },
        "HeadBucket",
    )

    assert service.check_s3_bucket_exists(
        "missing-bucket"
    ) is False


def test_check_s3_bucket_exists_does_not_treat_access_denied_as_missing():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.head_bucket.side_effect = ClientError(
        {
            "Error": {
                "Code": "403",
            }
        },
        "HeadBucket",
    )

    with pytest.raises(
        RuntimeError,
        match="S3 bucket existence check failed",
    ):
        service.check_s3_bucket_exists(
            "restricted-bucket"
        )
