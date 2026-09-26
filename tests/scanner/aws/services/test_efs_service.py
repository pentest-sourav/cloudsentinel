from unittest.mock import Mock

import pytest

from scanner.aws.services.efs import EFSService


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = EFSService(session)

    return service, client


def test_list_file_systems_paginates():
    service, client = make_service()

    client.describe_file_systems.side_effect = [
        {
            "FileSystems": [
                {"FileSystemId": "fs-1"},
            ],
            "NextMarker": "next",
        },
        {
            "FileSystems": [
                {"FileSystemId": "fs-2"},
            ],
        },
    ]

    assert service.list_file_systems() == [
        {"FileSystemId": "fs-1"},
        {"FileSystemId": "fs-2"},
    ]

    assert client.describe_file_systems.call_count == 2
    assert (
        client.describe_file_systems.call_args_list[1]
        .kwargs["Marker"]
        == "next"
    )


def test_list_access_points_paginates():
    service, client = make_service()

    client.describe_access_points.side_effect = [
        {
            "AccessPoints": [
                {"AccessPointId": "ap-1"},
            ],
            "NextToken": "next",
        },
        {
            "AccessPoints": [
                {"AccessPointId": "ap-2"},
            ],
        },
    ]

    assert service.list_access_points() == [
        {"AccessPointId": "ap-1"},
        {"AccessPointId": "ap-2"},
    ]

    assert (
        client.describe_access_points.call_args_list[1]
        .kwargs["NextToken"]
        == "next"
    )


def test_service_wraps_client_error():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.describe_file_systems.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "DescribeFileSystems",
    )

    with pytest.raises(
        RuntimeError,
        match="AWS EFS file-system discovery failed",
    ):
        service.list_file_systems()
