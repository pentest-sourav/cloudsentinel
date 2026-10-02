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


def test_collect_log_metric_alarm_controls_detects_root_chain():
    service = MagicMock()

    service.session = MagicMock()

    service.list_metric_alarms.return_value = [
        {
            "AlarmName": "root-usage-alarm",
            "AlarmArn": "arn:alarm:root",
            "MetricName": "RootUsage",
            "Namespace": "LogMetrics",
            "ComparisonOperator": (
                "GreaterThanOrEqualToThreshold"
            ),
            "Threshold": 1.0,
            "AlarmActions": [
                "arn:aws:sns:ap-south-1:"
                "123456789012:security-alerts"
            ],
        }
    ]

    service.list_metric_filters_for_log_group.return_value = [
        {
            "filterName": "root-usage",
            "filterPattern": (
                '{$.userIdentity.type="Root" && '
                '$.userIdentity.invokedBy NOT EXISTS && '
                '$.eventType !="AwsServiceEvent"}'
            ),
            "metricTransformations": [
                {
                    "metricName": "RootUsage",
                    "metricNamespace": "LogMetrics",
                    "metricValue": "1",
                    "defaultValue": "0",
                }
            ],
        }
    ]

    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = [
        {
            "TrailARN": "arn:aws:cloudtrail:ap-south-1:123:trail/test",
            "CloudWatchLogsLogGroupArn": (
                "arn:aws:logs:ap-south-1:123:"
                "log-group:/aws/cloudtrail:*"
            ),
        }
    ]

    sns_service = MagicMock()
    sns_service.list_subscriptions_by_topic.return_value = [
        {
            "SubscriptionArn": (
                "arn:aws:sns:ap-south-1:123:"
                "security-alerts:sub"
            )
        }
    ]

    from unittest.mock import patch

    with patch(
        "scanner.aws.collectors.cloudwatch.CloudTrailService",
        return_value=cloudtrail,
    ), patch(
        "scanner.aws.collectors.cloudwatch.SNSService",
        return_value=sns_service,
    ):
        results = CloudWatchDataCollector(
            service
        ).collect_log_metric_alarm_controls()

    root = next(
        item
        for item in results
        if item["control_id"] == "1"
    )

    assert root["compliant"] is True
    assert root["evidence"]["alarm_name"] == (
        "root-usage-alarm"
    )


def test_collect_log_metric_alarm_controls_marks_missing_chain():
    service = MagicMock()
    service.session = MagicMock()
    service.list_metric_alarms.return_value = []
    service.list_metric_filters_for_log_group.return_value = []

    cloudtrail = MagicMock()
    cloudtrail.describe_trails.return_value = []

    from unittest.mock import patch

    with patch(
        "scanner.aws.collectors.cloudwatch.CloudTrailService",
        return_value=cloudtrail,
    ):
        results = CloudWatchDataCollector(
            service
        ).collect_log_metric_alarm_controls()
        assert results == []
    assert all(
        item["compliant"] is False
        for item in results
    )
