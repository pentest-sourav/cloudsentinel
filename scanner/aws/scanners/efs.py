from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.efs_handlers import (
    EFS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.efs_registry import EFS_RULES
from scanner.aws.collectors.efs import EFSDataCollector
from scanner.aws.services.efs import EFSService


class EFSScanner:
    """
    Execute Amazon EFS security posture rules.
    """

    def __init__(
        self,
        service: EFSService,
    ):
        self.collector = EFSDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=EFS_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=EFS_RULES,
            collector=self.collector,
        )
