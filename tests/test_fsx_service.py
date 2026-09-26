from unittest.mock import Mock

import pytest

from scanner.aws.services.fsx import FSxService


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = FSxService(session)

    return service, client


def test_list_file_systems_paginates():
    service, client = make_service()

    client.describe_file_systems.side_effect = [
        {
            "FileSystems": [
                {"FileSystemId": "fs-1"},
            ],
            "NextToken": "next",
        },
        {
            "FileSystems": [
                {"FileSystemId": "fs-2"},
            ],
        },
    ]

    result = service.list_file_systems()

    assert result == [
        {"FileSystemId": "fs-1"},
        {"FileSystemId": "fs-2"},
    ]

    assert client.describe_file_systems.call_count == 2
    assert client.describe_file_systems.call_args_list[0].kwargs == {
        "MaxResults": 100,
    }
    assert client.describe_file_systems.call_args_list[1].kwargs == {
        "MaxResults": 100,
        "NextToken": "next",
    }


def test_list_file_systems_skips_non_dict_entries():
    service, client = make_service()

    client.describe_file_systems.return_value = {
        "FileSystems": [
            {"FileSystemId": "fs-1"},
            None,
            "invalid",
        ]
    }

    assert service.list_file_systems() == [
        {"FileSystemId": "fs-1"},
    ]


def test_list_file_systems_wraps_client_error():
    service, client = make_service()

    error = Exception("boom")
    client.describe_file_systems.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="Unexpected error during FSx file-system discovery",
    ):
        service.list_file_systems()
