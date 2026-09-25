from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.backup_handlers import (
    BACKUP_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.backup_registry import (
    BACKUP_RULES,
)
from scanner.aws.collectors.backup import (
    BackupDataCollector,
)
from scanner.aws.services.backup import BackupService


class BackupScanner:
    """
    Execute AWS Backup security posture rules.
    """

    def __init__(
        self,
        service: BackupService,
    ):
        self.collector = BackupDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=BACKUP_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=BACKUP_RULES,
            collector=self.collector,
        )
