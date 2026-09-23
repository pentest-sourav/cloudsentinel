from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.kms_handlers import (
    KMS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.kms_registry import KMS_RULES

from scanner.aws.collectors.kms import KMSDataCollector
from scanner.aws.services.kms import KMSService


class KMSScanner:
    """
    Runs registered KMS security rules against AWS KMS data.
    """

    def __init__(self, service: KMSService):
        self.collector = KMSDataCollector(service)

        self.executor = RuleExecutor(
            handlers=KMS_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=KMS_RULES,
            collector=self.collector,
        )
