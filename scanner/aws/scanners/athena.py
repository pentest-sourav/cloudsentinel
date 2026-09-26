from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.athena_handlers import (
    ATHENA_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.athena_registry import (
    ATHENA_RULES,
)
from scanner.aws.collectors.athena import (
    AthenaDataCollector,
)
from scanner.aws.services.athena import AthenaService


class AthenaScanner:
    """Runs registered AWS Athena security rules."""

    def __init__(
        self,
        service: AthenaService,
    ):
        self.collector = AthenaDataCollector(service)

        self.executor = RuleExecutor(
            handlers=ATHENA_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=ATHENA_RULES,
            collector=self.collector,
        )
