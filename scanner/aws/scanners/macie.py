from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.macie_handlers import (
    MACIE_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.macie_registry import (
    MACIE_RULES,
)

from scanner.aws.collectors.macie import (
    MacieDataCollector,
)
from scanner.aws.services.macie import (
    MacieService,
)


class MacieScanner:
    """
    Runs registered Amazon Macie security rules
    against account-level Macie configuration.
    """

    def __init__(
        self,
        service: MacieService,
    ):
        self.collector = MacieDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=MACIE_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=MACIE_RULES,
            collector=self.collector,
        )
