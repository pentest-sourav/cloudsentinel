from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.batch_handlers import (
    BATCH_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.batch_registry import (
    BATCH_RULES,
)
from scanner.aws.collectors.batch import BatchDataCollector
from scanner.aws.services.batch import BatchService


class BatchScanner:
    """Runs registered AWS Batch security rules."""

    def __init__(
        self,
        service: BatchService,
        rule_parameters: dict[str, dict[str, object]] | None = None,
    ):
        self.collector = BatchDataCollector(service)

        self.executor = RuleExecutor(
            handlers=BATCH_DATA_SOURCE_HANDLERS,
            rule_parameters=rule_parameters,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=BATCH_RULES,
            collector=self.collector,
        )
