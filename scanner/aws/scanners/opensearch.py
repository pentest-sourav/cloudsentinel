from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.opensearch_handlers import (
    OPENSEARCH_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.opensearch_registry import (
    OPENSEARCH_RULES,
)

from scanner.aws.collectors.opensearch import (
    OpenSearchDataCollector,
)
from scanner.aws.services.opensearch import OpenSearchService


class OpenSearchScanner:
    """
    Runs registered OpenSearch security rules against
    OpenSearch domains.
    """

    def __init__(self, service: OpenSearchService):
        self.collector = OpenSearchDataCollector(service)

        self.executor = RuleExecutor(
            handlers=OPENSEARCH_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=OPENSEARCH_RULES,
            collector=self.collector,
        )
