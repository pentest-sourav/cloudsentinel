from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.documentdb_handlers import (
    DOCUMENTDB_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.documentdb_registry import DOCUMENTDB_RULES

from scanner.aws.collectors.documentdb import DocumentDBDataCollector
from scanner.aws.services.documentdb import DocumentDBService


class DocumentDBScanner:
    """
    Execute the registered Amazon DocumentDB security rules.
    """

    def __init__(self, service: DocumentDBService):
        self.collector = DocumentDBDataCollector(service)
        self.executor = RuleExecutor(
            handlers=DOCUMENTDB_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=DOCUMENTDB_RULES,
            collector=self.collector,
        )
