from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.inspector_handlers import (
    INSPECTOR_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.inspector_registry import (
    INSPECTOR_RULES,
)

from scanner.aws.collectors.inspector import (
    InspectorDataCollector,
)
from scanner.aws.services.inspector import (
    InspectorService,
)


class InspectorScanner:
    """
    Runs registered Amazon Inspector security rules
    against account-level Inspector configuration.
    """

    def __init__(
        self,
        service: InspectorService,
    ):
        self.collector = InspectorDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=INSPECTOR_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=INSPECTOR_RULES,
            collector=self.collector,
        )
