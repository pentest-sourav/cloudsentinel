from typing import Any, Callable

from scanner.aws.collectors.sqs import SQSDataCollector


def collect_sqs_queues(
    collector: SQSDataCollector,
) -> list[dict]:
    return collector.collect_queues()


SQS_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[SQSDataCollector], Any],
] = {
    "sqs_queues": collect_sqs_queues,
}
