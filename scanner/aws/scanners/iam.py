from typing import Any

from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.iam_handlers import IAM_DATA_SOURCE_HANDLERS
from engine.rules.registry.iam_registry import IAM_RULES

from scanner.aws.collectors.iam import IAMDataCollector
from scanner.aws.services.iam import IAMService


class IAMScanner:
    def __init__(
        self,
        service: IAMService,
        rule_parameters: dict[str, dict[str, Any]] | None = None,
    ):
        self.collector = IAMDataCollector(service)
        self.executor = RuleExecutor(
            handlers=IAM_DATA_SOURCE_HANDLERS,
            rule_parameters=rule_parameters,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=IAM_RULES,
            collector=self.collector,
        )
