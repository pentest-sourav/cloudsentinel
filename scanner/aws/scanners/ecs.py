from typing import Any

from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.ecs_handlers import (
    ECS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.ecs_registry import ECS_RULES

from scanner.aws.collectors.ecs import ECSDataCollector
from scanner.aws.services.ecs import ECSService


class ECSScanner:
    """
    Runs all registered Amazon ECS security rules.

    rule_parameters allows AWS Security Hub-style control
    parameters to be supplied without coupling collection
    logic to rule configuration.
    """

    def __init__(
        self,
        service: ECSService,
        rule_parameters: dict[str, dict[str, Any]] | None = None,
    ):
        self.collector = ECSDataCollector(service)

        self.executor = RuleExecutor(
            handlers=ECS_DATA_SOURCE_HANDLERS,
            rule_parameters=rule_parameters,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=ECS_RULES,
            collector=self.collector,
        )
