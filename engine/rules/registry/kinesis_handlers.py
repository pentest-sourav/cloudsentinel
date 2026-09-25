from typing import Any, Callable

from scanner.aws.collectors.kinesis import KinesisDataCollector


def collect_kinesis_streams(
    collector: KinesisDataCollector,
) -> list[dict]:
    return collector.collect_streams()


KINESIS_DATA_SOURCE_HANDLERS: dict[
    str,
    Callable[[KinesisDataCollector], Any],
] = {
    "kinesis_streams": collect_kinesis_streams,
}
