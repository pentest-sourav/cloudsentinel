from scanner.aws.collectors.detective import (
    DetectiveDataCollector,
)


def collect_detective_graphs(
    collector: DetectiveDataCollector,
) -> list[dict]:
    return collector.collect_graphs()


DETECTIVE_DATA_SOURCE_HANDLERS = {
    "graphs": collect_detective_graphs,
}
