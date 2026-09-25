from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.ses_handlers import (
    SES_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.ses_registry import SES_RULES

from scanner.aws.collectors.ses import SESDataCollector
from scanner.aws.services.ses import SESService


class SESScanner:
    """
    Runs registered Amazon SES security rules.
    """

    def __init__(self, service: SESService):
        self.collector = SESDataCollector(service)

        self.executor = RuleExecutor(
            handlers=SES_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=SES_RULES,
            collector=self.collector,
        )
