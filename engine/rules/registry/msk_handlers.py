from typing import Any, Callable

from scanner.aws.collectors.msk import MSKDataCollector


def collect_msk_clusters(
    collector: MSKDataCollector,
) -> list[dict]:
    return collector.collect_clusters()


def collect_msk_connectors(
    collector: MSKDataCollector,
) -> list[dict]:
    return collector.collect_connectors()


MSK_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[MSKDataCollector], Any],
] = {
    "msk_clusters": collect_msk_clusters,
    "msk_connectors": collect_msk_connectors,
}
