from typing import Any, Callable

from scanner.aws.collectors.opensearch import (
    OpenSearchDataCollector,
)


def collect_opensearch_domains(
    collector: OpenSearchDataCollector,
) -> list[dict]:
    return collector.collect_domains()


OPENSEARCH_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[OpenSearchDataCollector], Any],
] = {
    "opensearch_domains": collect_opensearch_domains,
}
