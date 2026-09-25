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


CLOUDWATCH_DATA_SOURCE_HANDLERS = {
    "cloudwatch_alarms": collect_cloudwatch_alarms,
    "cloudwatch_log_groups": collect_cloudwatch_log_groups,
}
