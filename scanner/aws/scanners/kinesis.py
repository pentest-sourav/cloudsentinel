from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.kinesis_handlers import (
    KINESIS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.kinesis_registry import KINESIS_RULES

from scanner.aws.collectors.kinesis import KinesisDataCollector
from scanner.aws.services.kinesis import KinesisService


class KinesisScanner:
    """
    Runs registered Kinesis security rules against
    Amazon Kinesis Data Streams.
    """

    def __init__(self, service: KinesisService):
        self.collector = KinesisDataCollector(service)

        self.executor = RuleExecutor(
            handlers=KINESIS_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=KINESIS_RULES,
            collector=self.collector,
        )
