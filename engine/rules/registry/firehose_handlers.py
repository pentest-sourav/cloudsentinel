from scanner.aws.collectors.firehose import FirehoseDataCollector


def collect_firehose_delivery_streams(
    collector: FirehoseDataCollector,
) -> list[dict]:
    return collector.collect_delivery_streams()


FIREHOSE_DATA_SOURCE_HANDLERS = {
    "firehose_delivery_streams": collect_firehose_delivery_streams,
}
