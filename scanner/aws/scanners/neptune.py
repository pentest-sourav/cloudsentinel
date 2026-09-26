from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.neptune_handlers import (
    NEPTUNE_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.neptune_registry import NEPTUNE_RULES

from scanner.aws.collectors.neptune import NeptuneDataCollector
from scanner.aws.services.neptune import NeptuneService


class NeptuneScanner:
    """
    Runs registered Amazon Neptune security rules.
    """

    def __init__(self, service: NeptuneService):
        self.collector = NeptuneDataCollector(service)

        self.executor = RuleExecutor(
            handlers=NEPTUNE_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=NEPTUNE_RULES,
            collector=self.collector,
        )
