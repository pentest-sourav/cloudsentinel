from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.fsx_handlers import (
    FSX_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.fsx_registry import FSX_RULES
from scanner.aws.collectors.fsx import FSxDataCollector
from scanner.aws.services.fsx import FSxService


class FSxScanner:
    """
    Execute Amazon FSx security posture rules.
    """

    def __init__(
        self,
        service: FSxService,
    ):
        self.collector = FSxDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=FSX_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=FSX_RULES,
            collector=self.collector,
        )
