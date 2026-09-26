from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.emr_handlers import (
    EMR_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.emr_registry import EMR_RULES

from scanner.aws.collectors.emr import EMRDataCollector
from scanner.aws.services.emr import EMRService


class EMRScanner:
    """
    Runs registered Amazon EMR security rules.
    """

    def __init__(self, service: EMRService):
        self.collector = EMRDataCollector(service)

        self.executor = RuleExecutor(
            handlers=EMR_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=EMR_RULES,
            collector=self.collector,
        )
