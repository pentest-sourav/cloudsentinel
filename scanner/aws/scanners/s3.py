from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.s3_handlers import S3_DATA_SOURCE_HANDLERS
from engine.rules.registry.s3_registry import S3_RULES

from scanner.aws.collectors.s3 import S3DataCollector
from scanner.aws.services.s3 import S3Service


class S3Scanner:
    def __init__(self, service: S3Service):
        self.collector = S3DataCollector(service)
        self.executor = RuleExecutor(
            handlers=S3_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=S3_RULES,
            collector=self.collector,
        )
