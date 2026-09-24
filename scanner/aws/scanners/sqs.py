from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.sqs_handlers import (
    SQS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.sqs_registry import SQS_RULES

from scanner.aws.collectors.sqs import SQSDataCollector
from scanner.aws.services.sqs import SQSService


class SQSScanner:
    """
    Runs registered SQS security rules against AWS SQS queues.
    """

    def __init__(self, service: SQSService):
        self.collector = SQSDataCollector(service)

        self.executor = RuleExecutor(
            handlers=SQS_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=SQS_RULES,
            collector=self.collector,
        )
