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

    def __init__(self, service: DetectiveService):
        self.collector = DetectiveDataCollector(service)

        self.executor = RuleExecutor(
            handlers=DETECTIVE_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=DETECTIVE_RULES,
            collector=self.collector,
        )
