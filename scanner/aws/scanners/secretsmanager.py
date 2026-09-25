from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.secretsmanager_handlers import (
    SECRETSMANAGER_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.secretsmanager_registry import (
    SECRETSMANAGER_RULES,
)

from scanner.aws.collectors.secretsmanager import (
    SecretsManagerDataCollector,
)
from scanner.aws.services.secretsmanager import (
    SecretsManagerService,
)


class SecretsManagerScanner:
    """
    Runs registered Secrets Manager security rules.
    """

    def __init__(
        self,
        service: SecretsManagerService,
    ):
        self.collector = SecretsManagerDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=SECRETSMANAGER_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=SECRETSMANAGER_RULES,
            collector=self.collector,
        )
