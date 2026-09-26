from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.mq_handlers import (
    MQ_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.mq_registry import MQ_RULES
from scanner.aws.collectors.mq import MQDataCollector
from scanner.aws.services.mq import MQService


class MQScanner:
    """
    Execute Amazon MQ security posture rules.
    """

    def __init__(self, service: MQService):
        self.collector = MQDataCollector(service)
        self.executor = RuleExecutor(
            handlers=MQ_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=MQ_RULES,
            collector=self.collector,
        )
