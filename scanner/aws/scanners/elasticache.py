from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.elasticache_handlers import (
    ELASTICACHE_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.elasticache_registry import (
    ELASTICACHE_RULES,
)

from scanner.aws.collectors.elasticache import (
    ElastiCacheDataCollector,
)
from scanner.aws.services.elasticache import ElastiCacheService


class ElastiCacheScanner:
    def __init__(self, service: ElastiCacheService):
        self.collector = ElastiCacheDataCollector(service)
        self.executor = RuleExecutor(
            handlers=ELASTICACHE_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        findings.extend(
            self.executor.execute_registry(
                registry=ELASTICACHE_RULES,
                collector=self.collector,
            )
        )

        return findings
