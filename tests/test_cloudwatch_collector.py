from unittest.mock import MagicMock

from scanner.aws.collectors.cloudwatch import (
    CloudWatchDataCollector,
)


def test_collect_alarms_normalizes_security_fields():
    service = MagicMock()

    service.list_metric_alarms.return_value = [
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
            "OKActions": [],
            "InsufficientDataActions": [],
            "StateValue": "OK",
            "StateReason": "test",
            "MetricName": "RootUsage",
            "Namespace": "CloudSentinel",
        }
    ]

    result = CloudWatchDataCollector(
        service
    ).collect_alarms()

    assert result == [
        {
            "resource_id": "root-usage",
            "resource_type": "cloudwatch_alarm",
            "alarm_arn": (
                "arn:aws:cloudwatch:ap-south-1:"
                "123456789012:alarm:root-usage"
            ),
            "alarm_name": "root-usage",
            "actions_enabled": True,
            "alarm_actions": [
                "arn:aws:sns:ap-south-1:"
                "123456789012:security-alerts"
            ],
            "ok_actions": [],
            "insufficient_data_actions": [],
            "state_value": "OK",
            "state_reason": "test",
            "metric_name": "RootUsage",
            "namespace": "CloudSentinel",
        }
    ]


def test_collect_log_groups_normalizes_retention():
    service = MagicMock()

    service.list_log_groups.return_value = [
        {
            "logGroupName": "/aws/cloudsentinel",
            "retentionInDays": 365,
            "storedBytes": 1024,
            "creationTime": 1760000000000,
            "arn": (
                "arn:aws:logs:ap-south-1:"
                "123456789012:log-group:/aws/cloudsentinel:*"
            ),
        }
    ]

    result = CloudWatchDataCollector(
        service
    ).collect_log_groups()

    assert result == [
        {
            "resource_id": "/aws/cloudsentinel",
            "resource_type": "cloudwatch_log_group",
            "log_group_name": "/aws/cloudsentinel",
            "retention_in_days": 365,
            "stored_bytes": 1024,
            "creation_time": 1760000000000,
            "arn": (
                "arn:aws:logs:ap-south-1:"
                "123456789012:log-group:/aws/cloudsentinel:*"
            ),
        }
    ]


def test_collect_alarms_is_cached():
    service = MagicMock()

    service.list_metric_alarms.return_value = [
        {
            "AlarmName": "alarm-1",
            "AlarmActions": [],
            "ActionsEnabled": False,
        }
    ]

    collector = CloudWatchDataCollector(service)

    first = collector.collect_alarms()
    second = collector.collect_alarms()

    assert first == second
    service.list_metric_alarms.assert_called_once()


def test_collect_log_groups_is_cached():
    service = MagicMock()

    service.list_log_groups.return_value = [
        {
            "logGroupName": "/aws/test",
            "retentionInDays": 365,
        }
    ]

    collector = CloudWatchDataCollector(service)

    first = collector.collect_log_groups()
    second = collector.collect_log_groups()

    assert first == second
    service.list_log_groups.assert_called_once()


def test_collect_alarms_skips_entries_without_alarm_name():
    service = MagicMock()

    service.list_metric_alarms.return_value = [
        {
            "AlarmActions": [],
            "ActionsEnabled": False,
        },
        {
            "AlarmName": "valid-alarm",
            "AlarmActions": [],
            "ActionsEnabled": False,
        },
    ]

    result = CloudWatchDataCollector(
        service
    ).collect_alarms()

    assert len(result) == 1
    assert result[0]["resource_id"] == "valid-alarm"
