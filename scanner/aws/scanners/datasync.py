from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.datasync_handlers import (
    DATASYNC_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.datasync_registry import (
    DATASYNC_RULES,
)
from scanner.aws.collectors.datasync import (
    DataSyncDataCollector,
)
from scanner.aws.services.datasync import DataSyncService


class DataSyncScanner:
    """Runs registered AWS DataSync security rules."""

    def __init__(self, service: DataSyncService):
        self.collector = DataSyncDataCollector(service)

        self.executor = RuleExecutor(
            handlers=DATASYNC_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=DATASYNC_RULES,
            collector=self.collector,
        )
