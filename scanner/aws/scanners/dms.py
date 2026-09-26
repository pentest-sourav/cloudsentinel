from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.dms_handlers import (
    DMS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.dms_registry import DMS_RULES
from scanner.aws.collectors.dms import DMSDataCollector
from scanner.aws.services.dms import DMSService


class DMSScanner:
    """Runs registered AWS DMS security rules."""

    def __init__(self, service: DMSService):
        self.collector = DMSDataCollector(service)

        self.executor = RuleExecutor(
            handlers=DMS_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=DMS_RULES,
            collector=self.collector,
        )
