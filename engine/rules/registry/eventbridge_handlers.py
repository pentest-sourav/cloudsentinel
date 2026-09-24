from typing import Any, Callable

from scanner.aws.collectors.eventbridge import (
    EventBridgeDataCollector,
)


def collect_eventbridge_event_buses(
    collector: EventBridgeDataCollector,
) -> list[dict]:
    return collector.collect_event_buses()


def collect_eventbridge_endpoints(
    collector: EventBridgeDataCollector,
) -> list[dict]:
    return collector.collect_endpoints()


EVENTBRIDGE_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[EventBridgeDataCollector], Any],
] = {
    "eventbridge_event_buses": (
        collect_eventbridge_event_buses
    ),
    "eventbridge_global_endpoints": (
        collect_eventbridge_endpoints
    ),
}
