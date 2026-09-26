from unittest.mock import Mock

from scanner.aws.collectors.datasync import (
    DataSyncDataCollector,
)


def _service():
    service = Mock()

    service.list_tasks.return_value = [
        {
            "TaskArn": "arn:task",
            "Name": "migration-task",
            "TaskMode": "BASIC",
        }
    ]

    service.describe_task.return_value = {
        "TaskArn": "arn:task",
        "Name": "migration-task",
        "TaskMode": "BASIC",
        "Options": {
            "LogLevel": "TRANSFER",
        },
        "CloudWatchLogGroupArn": (
            "arn:aws:logs:region:account:"
            "log-group:/aws/datasync/task"
        ),
    }

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
        "aws:createdBy": "system",
    }

    return service


def test_collect_tasks():
    service = _service()

    result = DataSyncDataCollector(
        service
    ).collect_tasks()

    assert result == [
        {
            "resource_name": "migration-task",
            "resource_arn": "arn:task",
            "resource_type": "AWS::DataSync::Task",
            "task_mode": "BASIC",
            "status": None,
            "log_level": "TRANSFER",
            "cloudwatch_log_group_arn": (
                "arn:aws:logs:region:account:"
                "log-group:/aws/datasync/task"
            ),
            "tags": {
                "Environment": "prod",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_system_tags_are_ignored():
    service = _service()

    service.list_tags_for_resource.return_value = {
        "aws:createdBy": "system",
    }

    result = DataSyncDataCollector(
        service
    ).collect_tasks()

    assert result[0]["tags"] == {}
    assert result[0]["tag_data_available"] is True
    assert result[0]["has_non_system_tags"] is False


def test_collector_caches_discovery_and_details():
    service = _service()

    collector = DataSyncDataCollector(service)

    collector.collect_tasks()
    collector.collect_tasks()

    service.list_tasks.assert_called_once()
    service.describe_task.assert_called_once_with(
        "arn:task"
    )
    service.list_tags_for_resource.assert_called_once_with(
        "arn:task"
    )
