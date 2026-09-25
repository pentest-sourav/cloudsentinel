from unittest.mock import MagicMock

from engine.rules.registry.cloudwatch_handlers import (
    collect_cloudwatch_alarms,
    collect_cloudwatch_log_groups,
)


def test_collect_cloudwatch_alarms_calls_collector():
    collector = MagicMock()

    expected = [
        {
            "resource_id": "alarm-1",
            "resource_type": "cloudwatch_alarm",
        }
    ]

    collector.collect_alarms.return_value = expected

    result = collect_cloudwatch_alarms(collector)

    assert result == expected
    collector.collect_alarms.assert_called_once_with()


def test_collect_cloudwatch_log_groups_calls_collector():
    collector = MagicMock()

    expected = [
        {
            "resource_id": "/aws/test",
            "resource_type": "cloudwatch_log_group",
        }
    ]

    collector.collect_log_groups.return_value = expected

    result = collect_cloudwatch_log_groups(
        collector
    )

    assert result == expected
    collector.collect_log_groups.assert_called_once_with()
