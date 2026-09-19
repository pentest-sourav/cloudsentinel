from unittest.mock import Mock

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.services.cloudtrail import CloudTrailService


def create_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = CloudTrailService(session)

    return service, client


def test_describe_trails_returns_trails():
    service, client = create_service()

    client.describe_trails.return_value = {
        "trailList": [
            {
                "Name": "cloudtrail-main",
                "TrailARN": "arn:aws:cloudtrail:eu-north-1:123456789012:trail/cloudtrail-main",
                "HomeRegion": "eu-north-1",
            }
        ]
    }

    trails = service.describe_trails()

    assert len(trails) == 1
    assert trails[0]["Name"] == "cloudtrail-main"

    client.describe_trails.assert_called_once_with(
        includeShadowTrails=True
    )


def test_describe_trails_returns_empty_list():
    service, client = create_service()

    client.describe_trails.return_value = {
        "trailList": []
    }

    trails = service.describe_trails()

    assert trails == []


def test_describe_trails_handles_client_error():
    service, client = create_service()

    client.describe_trails.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "DescribeTrails",
    )

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: Access denied",
    ):
        service.describe_trails()


def test_describe_trails_handles_botocore_error():
    service, client = create_service()

    client.describe_trails.side_effect = BotoCoreError()

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during CloudTrail discovery",
    ):
        service.describe_trails()


def test_get_trail_status_returns_status():
    service, client = create_service()

    client.get_trail_status.return_value = {
        "IsLogging": True,
        "LatestDeliveryTime": "2026-09-19T10:00:00Z",
    }

    status = service.get_trail_status(
        "arn:aws:cloudtrail:eu-north-1:123456789012:trail/cloudtrail-main"
    )

    assert status["IsLogging"] is True

    client.get_trail_status.assert_called_once_with(
        Name="arn:aws:cloudtrail:eu-north-1:123456789012:trail/cloudtrail-main"
    )


def test_get_trail_status_handles_client_error():
    service, client = create_service()

    client.get_trail_status.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "GetTrailStatus",
    )

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: Access denied",
    ):
        service.get_trail_status(
            "arn:aws:cloudtrail:eu-north-1:123456789012:trail/cloudtrail-main"
        )
