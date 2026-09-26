from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.msk_handlers import (
    MSK_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.msk_registry import MSK_RULES

from scanner.aws.collectors.msk import MSKDataCollector
from scanner.aws.services.msk import MSKService


class MSKScanner:
    """
    Runs registered MSK security rules against
    Amazon MSK clusters and MSK Connect connectors.
    """

    def __init__(self, service: MSKService):
        self.collector = MSKDataCollector(service)

        self.executor = RuleExecutor(
            handlers=MSK_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=MSK_RULES,
            collector=self.collector,
        )
