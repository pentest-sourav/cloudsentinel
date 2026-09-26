from scanner.aws.collectors.mq import MQDataCollector


def collect_mq_brokers(
    collector: MQDataCollector,
) -> list[dict]:
    return collector.collect_brokers()


MQ_DATA_SOURCE_HANDLERS = {
    "mq_brokers": collect_mq_brokers,
}
