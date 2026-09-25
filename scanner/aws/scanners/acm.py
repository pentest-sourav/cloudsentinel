from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.acm_handlers import (
    ACM_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.acm_registry import ACM_RULES

from scanner.aws.collectors.acm import ACMDataCollector
from scanner.aws.services.acm import ACMService


class ACMScanner:
    """
    Runs registered ACM security rules.
    """

    def __init__(self, service: ACMService):
        self.collector = ACMDataCollector(service)

        self.executor = RuleExecutor(
            handlers=ACM_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=ACM_RULES,
            collector=self.collector,
        )
