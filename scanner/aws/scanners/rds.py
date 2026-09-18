from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.rds_handlers import (
    RDS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.rds_registry import RDS_RULES

from scanner.aws.collectors.rds import RDSDataCollector
from scanner.aws.services.rds import RDSService


class RDSScanner:
    """
    Runs registered RDS security rules against AWS data.

    AWS collection, rule execution, and finding generation
    remain separated through the existing CloudSentinel
    architecture.
    """

    def __init__(self, service: RDSService):
        self.collector = RDSDataCollector(service)

        self.executor = RuleExecutor(
            handlers=RDS_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=RDS_RULES,
            collector=self.collector,
        )
