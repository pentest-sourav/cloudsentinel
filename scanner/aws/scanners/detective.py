from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.detective_handlers import (
    DETECTIVE_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.detective_registry import (
    DETECTIVE_RULES,
)
from scanner.aws.collectors.detective import (
    DetectiveDataCollector,
)
from scanner.aws.services.detective import DetectiveService


class DetectiveScanner:
    """Runs registered Amazon Detective security rules."""

    def __init__(
        self,
        service: DetectiveService,
        rule_parameters: dict[str, dict[str, object]] | None = None,
    ):
        self.collector = DetectiveDataCollector(service)

        self.executor = RuleExecutor(
            handlers=DETECTIVE_DATA_SOURCE_HANDLERS,
            rule_parameters=rule_parameters,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=DETECTIVE_RULES,
            collector=self.collector,
        )
