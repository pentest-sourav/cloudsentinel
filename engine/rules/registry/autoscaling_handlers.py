from typing import Any

from scanner.aws.collectors.autoscaling import (
    AutoScalingDataCollector,
)


def collect_autoscaling_groups(
    collector: AutoScalingDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_auto_scaling_groups()


AUTOSCALING_DATA_SOURCE_HANDLERS = {
    "autoscaling_groups": collect_autoscaling_groups,
}
