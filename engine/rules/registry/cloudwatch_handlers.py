from typing import Any

from scanner.aws.collectors.cloudwatch import (
    CloudWatchDataCollector,
)


def collect_cloudwatch_alarms(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_alarms()


def collect_cloudwatch_log_groups(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_log_groups()


def _collect_cloudwatch_log_metric_alarm_control(
    collector: CloudWatchDataCollector,
    control_id: int,
) -> list[dict[str, Any]]:
    return [
        item
        for item in collector.collect_log_metric_alarm_controls()
        if str(item.get("control_id")) == str(control_id)
    ]

def collect_cloudwatch_log_metric_alarm_control_1(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        1,
    )


def collect_cloudwatch_log_metric_alarm_control_2(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        2,
    )


def collect_cloudwatch_log_metric_alarm_control_3(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        3,
    )


def collect_cloudwatch_log_metric_alarm_control_4(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        4,
    )


def collect_cloudwatch_log_metric_alarm_control_5(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        5,
    )


def collect_cloudwatch_log_metric_alarm_control_6(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        6,
    )


def collect_cloudwatch_log_metric_alarm_control_7(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        7,
    )


def collect_cloudwatch_log_metric_alarm_control_8(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        8,
    )


def collect_cloudwatch_log_metric_alarm_control_9(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        9,
    )


def collect_cloudwatch_log_metric_alarm_control_10(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        10,
    )


def collect_cloudwatch_log_metric_alarm_control_11(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        11,
    )


def collect_cloudwatch_log_metric_alarm_control_12(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        12,
    )


def collect_cloudwatch_log_metric_alarm_control_13(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        13,
    )


def collect_cloudwatch_log_metric_alarm_control_14(
    collector: CloudWatchDataCollector,
) -> list[dict[str, Any]]:
    return _collect_cloudwatch_log_metric_alarm_control(
        collector,
        14,
    )


CLOUDWATCH_DATA_SOURCE_HANDLERS = {
    "cloudwatch_alarms": collect_cloudwatch_alarms,
    "cloudwatch_log_groups": collect_cloudwatch_log_groups,
    "cloudwatch_log_metric_alarm_control_1":
        collect_cloudwatch_log_metric_alarm_control_1,
    "cloudwatch_log_metric_alarm_control_2":
        collect_cloudwatch_log_metric_alarm_control_2,
    "cloudwatch_log_metric_alarm_control_3":
        collect_cloudwatch_log_metric_alarm_control_3,
    "cloudwatch_log_metric_alarm_control_4":
        collect_cloudwatch_log_metric_alarm_control_4,
    "cloudwatch_log_metric_alarm_control_5":
        collect_cloudwatch_log_metric_alarm_control_5,
    "cloudwatch_log_metric_alarm_control_6":
        collect_cloudwatch_log_metric_alarm_control_6,
    "cloudwatch_log_metric_alarm_control_7":
        collect_cloudwatch_log_metric_alarm_control_7,
    "cloudwatch_log_metric_alarm_control_8":
        collect_cloudwatch_log_metric_alarm_control_8,
    "cloudwatch_log_metric_alarm_control_9":
        collect_cloudwatch_log_metric_alarm_control_9,
    "cloudwatch_log_metric_alarm_control_10":
        collect_cloudwatch_log_metric_alarm_control_10,
    "cloudwatch_log_metric_alarm_control_11":
        collect_cloudwatch_log_metric_alarm_control_11,
    "cloudwatch_log_metric_alarm_control_12":
        collect_cloudwatch_log_metric_alarm_control_12,
    "cloudwatch_log_metric_alarm_control_13":
        collect_cloudwatch_log_metric_alarm_control_13,
    "cloudwatch_log_metric_alarm_control_14":
        collect_cloudwatch_log_metric_alarm_control_14,
}
