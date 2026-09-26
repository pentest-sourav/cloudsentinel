from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.detective import DetectiveService


def _error():
    return ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "ListGraphs",
    )


def _service(client):
    session = Mock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.detective.create_aws_client",
            lambda *_: client,
        )
        return DetectiveService(session)


def test_list_graphs_handles_pagination():
    client = Mock()
    client.list_graphs.side_effect = [
        {
            "GraphList": [
                {
                    "Arn": "arn:graph-1",
                    "CreatedTime": "time-1",
                }
            ],
            "NextToken": "next",
        },
        {
            "GraphList": [
                {
                    "Arn": "arn:graph-2",
                    "CreatedTime": "time-2",
                }
            ]
        },
    ]

    service = _service(client)

    assert service.list_graphs() == [
        {
            "Arn": "arn:graph-1",
            "CreatedTime": "time-1",
        },
        {
            "Arn": "arn:graph-2",
            "CreatedTime": "time-2",
        },
    ]

    assert client.list_graphs.call_count == 2
    client.list_graphs.assert_any_call()
    client.list_graphs.assert_any_call(
        NextToken="next"
    )


def test_list_tags_for_resource():
    client = Mock()
    client.list_tags_for_resource.return_value = {
        "Tags": {
            "Environment": "prod",
            "Owner": "security",
        }
    }

    service = _service(client)

    assert service.list_tags_for_resource(
        "arn:graph"
    ) == {
        "Environment": "prod",
        "Owner": "security",
    }

    client.list_tags_for_resource.assert_called_once_with(
        ResourceArn="arn:graph"
    )


def test_empty_tag_arn_returns_empty():
    client = Mock()

    service = _service(client)

    assert service.list_tags_for_resource("") == {}

    client.list_tags_for_resource.assert_not_called()


def test_api_error_is_normalized():
    client = Mock()
    client.list_graphs.side_effect = _error()

    service = _service(client)

    with pytest.raises(
        RuntimeError,
        match="Detective graph discovery failed",
    ):
        service.list_graphs()
