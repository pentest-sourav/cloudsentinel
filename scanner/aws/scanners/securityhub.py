from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.securityhub_handlers import (
    SECURITYHUB_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.securityhub_registry import (
    SECURITYHUB_RULES,
)
from scanner.aws.collectors.securityhub import (
    SecurityHubDataCollector,
)
from scanner.aws.services.securityhub import (
    SecurityHubService,
)


class SecurityHubScanner:
    """Runs registered AWS Security Hub security rules."""

    def __init__(
        self,
        service: SecurityHubService,
    ):
        self.collector = SecurityHubDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=SECURITYHUB_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=SECURITYHUB_RULES,
            collector=self.collector,
        )
