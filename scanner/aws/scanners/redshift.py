from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.redshift_handlers import (
    REDSHIFT_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.redshift_registry import REDSHIFT_RULES

from scanner.aws.collectors.redshift import RedshiftDataCollector
from scanner.aws.services.redshift import RedshiftService


class RedshiftScanner:
    """
    Run registered Redshift security rules against collected AWS data.
    """

    def __init__(self, service: RedshiftService):
        self.collector = RedshiftDataCollector(service)

        self.executor = RuleExecutor(
            handlers=REDSHIFT_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=REDSHIFT_RULES,
            collector=self.collector,
        )
