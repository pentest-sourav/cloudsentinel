from unittest.mock import MagicMock

from scanner.aws.services.cloudwatch import (
    CloudWatchService,
)


def test_list_metric_alarms_returns_alarms():
    service = CloudWatchService.__new__(
        CloudWatchService
    )
    service.cloudwatch_client = MagicMock()
    service.logs_client = MagicMock()

    service.cloudwatch_client.describe_alarms.return_value = {
        "MetricAlarms": [
            {
                "AlarmName": "root-usage",
                "AlarmArn": (
                    "arn:aws:cloudwatch:ap-south-1:"
                    "123456789012:alarm:root-usage"
                ),
                "ActionsEnabled": True,
                "AlarmActions": [
                    "arn:aws:sns:ap-south-1:"
                    "123456789012:security-alerts"
                ],
            }
        ]
    }

    result = service.list_metric_alarms()

    assert len(result) == 1
    assert result[0]["AlarmName"] == "root-usage"

    service.cloudwatch_client.describe_alarms.assert_called_once_with(
        MaxRecords=100,
    )


def test_list_metric_alarms_handles_multiple_pages():
    service = CloudWatchService.__new__(
        CloudWatchService
    )
    service.cloudwatch_client = MagicMock()
    service.logs_client = MagicMock()

    service.cloudwatch_client.describe_alarms.side_effect = [
        {
            "MetricAlarms": [
                {"AlarmName": "alarm-1"}
            ],
            "NextToken": "page-2",
        },
        {
            "MetricAlarms": [
                {"AlarmName": "alarm-2"}
            ]
        },
    ]

    result = service.list_metric_alarms()

    assert [
        alarm["AlarmName"]
        for alarm in result
    ] == [
        "alarm-1",
        "alarm-2",
    ]

    assert (
        service.cloudwatch_client
        .describe_alarms.call_count
        == 2
    )

    service.cloudwatch_client.describe_alarms.assert_any_call(
        MaxRecords=100,
    )

    service.cloudwatch_client.describe_alarms.assert_any_call(
        MaxRecords=100,
        NextToken="page-2",
    )


def test_list_log_groups_returns_log_groups():
    service = CloudWatchService.__new__(
        CloudWatchService
    )
    service.cloudwatch_client = MagicMock()
    service.logs_client = MagicMock()

    service.logs_client.describe_log_groups.return_value = {
        "logGroups": [
            {
                "logGroupName": "/aws/cloudsentinel",
                "retentionInDays": 365,
            }
        ]
    }

    result = service.list_log_groups()

    assert len(result) == 1
    assert (
        result[0]["logGroupName"]
        == "/aws/cloudsentinel"
    )

    service.logs_client.describe_log_groups.assert_called_once_with(
        limit=50,
    )


def test_list_log_groups_handles_multiple_pages():
    service = CloudWatchService.__new__(
        CloudWatchService
    )
    service.cloudwatch_client = MagicMock()
    service.logs_client = MagicMock()

    service.logs_client.describe_log_groups.side_effect = [
        {
            "logGroups": [
                {
                    "logGroupName": "/aws/one"
                }
            ],
            "nextToken": "page-2",
        },
        {
            "logGroups": [
                {
                    "logGroupName": "/aws/two"
                }
            ]
        },
    ]

    result = service.list_log_groups()

    assert [
        group["logGroupName"]
        for group in result
    ] == [
        "/aws/one",
        "/aws/two",
    ]

    assert (
        service.logs_client
        .describe_log_groups.call_count
        == 2
    )


def test_empty_metric_alarm_response_returns_empty_list():
    service = CloudWatchService.__new__(
        CloudWatchService
    )
    service.cloudwatch_client = MagicMock()
    service.logs_client = MagicMock()

    service.cloudwatch_client.describe_alarms.return_value = {}

    assert service.list_metric_alarms() == []


def test_empty_log_group_response_returns_empty_list():
    service = CloudWatchService.__new__(
        CloudWatchService
    )
    service.cloudwatch_client = MagicMock()
    service.logs_client = MagicMock()

    service.logs_client.describe_log_groups.return_value = {}

    assert service.list_log_groups() == []
