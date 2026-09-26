from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.glue_handlers import (
    GLUE_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.glue_registry import GLUE_RULES
from scanner.aws.collectors.glue import GlueDataCollector
from scanner.aws.services.glue import GlueService


class GlueScanner:
    """
    Runs registered AWS Glue security rules.
    """

    def __init__(self, service: GlueService):
        self.collector = GlueDataCollector(service)

        self.executor = RuleExecutor(
            handlers=GLUE_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=GLUE_RULES,
            collector=self.collector,
        )
