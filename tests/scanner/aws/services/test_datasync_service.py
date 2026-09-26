from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.datasync import DataSyncService


def _error():
    return ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "ListTasks",
    )


def _service(client):
    session = Mock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.datasync.create_aws_client",
            lambda *_: client,
        )
        return DataSyncService(session)


def test_list_tasks():
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "Tasks": [
                {
                    "TaskArn": "arn:task-1",
                    "Name": "task-1",
                }
            ]
        },
        {
            "Tasks": [
                {
                    "TaskArn": "arn:task-2",
                    "Name": "task-2",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    service = _service(client)

    assert service.list_tasks() == [
        {
            "TaskArn": "arn:task-1",
            "Name": "task-1",
        },
        {
            "TaskArn": "arn:task-2",
            "Name": "task-2",
        },
    ]

    client.get_paginator.assert_called_once_with(
        "list_tasks"
    )


def test_describe_task():
    client = Mock()

    client.describe_task.return_value = {
        "TaskArn": "arn:task",
        "TaskMode": "BASIC",
        "CloudWatchLogGroupArn": (
            "arn:aws:logs:region:account:log-group:/datasync"
        ),
        "Options": {
            "LogLevel": "BASIC",
        },
    }

    service = _service(client)

    assert service.describe_task("arn:task") == (
        client.describe_task.return_value
    )

    client.describe_task.assert_called_once_with(
        TaskArn="arn:task"
    )


def test_list_tags_for_resource():
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ]
        },
        {
            "Tags": [
                {
                    "Key": "Owner",
                    "Value": "security",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    service = _service(client)

    assert service.list_tags_for_resource(
        "arn:task"
    ) == {
        "Environment": "prod",
        "Owner": "security",
    }

    client.get_paginator.assert_called_once_with(
        "list_tags_for_resource"
    )


def test_empty_tag_arn_returns_empty():
    client = Mock()

    service = _service(client)

    assert service.list_tags_for_resource("") == {}

    client.get_paginator.assert_not_called()


def test_api_error_is_normalized():
    client = Mock()
    client.get_paginator.side_effect = _error()

    service = _service(client)

    with pytest.raises(
        RuntimeError,
        match="AWS DataSync list_tasks failed",
    ):
        service.list_tasks()
