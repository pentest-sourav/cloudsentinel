from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.sns_handlers import SNS_DATA_SOURCE_HANDLERS
from engine.rules.registry.sns_registry import SNS_RULES

from scanner.aws.collectors.sns import SNSDataCollector
from scanner.aws.services.sns import SNSService


class SNSScanner:
    def __init__(self, service: SNSService):
        self.collector = SNSDataCollector(service)
        self.executor = RuleExecutor(
            handlers=SNS_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=SNS_RULES,
            collector=self.collector,
        )
