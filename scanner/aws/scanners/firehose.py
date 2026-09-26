from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.firehose_handlers import (
    FIREHOSE_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.firehose_registry import FIREHOSE_RULES

from scanner.aws.collectors.firehose import FirehoseDataCollector
from scanner.aws.services.firehose import FirehoseService


class FirehoseScanner:
    """
    Run registered Firehose security rules against collected AWS data.
    """

    def __init__(self, service: FirehoseService):
        self.collector = FirehoseDataCollector(service)

        self.executor = RuleExecutor(
            handlers=FIREHOSE_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=FIREHOSE_RULES,
            collector=self.collector,
        )
