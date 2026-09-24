from engine.rules.registry.sqs_handlers import (
    SQS_DATA_SOURCE_HANDLERS,
    collect_sqs_queues,
)
from scanner.aws.collectors.sqs import SQSDataCollector


def test_sqs_handler_is_registered():
    assert "sqs_queues" in SQS_DATA_SOURCE_HANDLERS
    assert SQS_DATA_SOURCE_HANDLERS["sqs_queues"] is collect_sqs_queues


def test_sqs_handler_uses_collector_method():
    assert collect_sqs_queues is not None
    assert SQSDataCollector.collect_queues is not None
