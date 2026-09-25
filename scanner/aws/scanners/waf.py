from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.waf_handlers import (
    WAF_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.waf_registry import WAF_RULES

from scanner.aws.collectors.waf import WAFDataCollector
from scanner.aws.services.waf import WAFService


class WAFScanner:
    """
    Runs registered AWS WAFv2 security rules.
    """

    def __init__(self, service: WAFService):
        self.collector = WAFDataCollector(service)

        self.executor = RuleExecutor(
            handlers=WAF_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=WAF_RULES,
            collector=self.collector,
        )
