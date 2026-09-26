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
