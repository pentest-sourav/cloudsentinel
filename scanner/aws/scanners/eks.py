from typing import Any

from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.eks_handlers import (
    EKS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.eks_registry import EKS_RULES

from scanner.aws.collectors.eks import EKSDataCollector
from scanner.aws.services.eks import EKSService


class EKSScanner:
    """
    Runs registered Amazon EKS security rules.

    rule_parameters allows AWS Security Hub-style control
    parameters to be supplied without coupling collection
    logic to rule configuration.
    """

    def __init__(
        self,
        service: EKSService,
        rule_parameters: dict[str, dict[str, Any]] | None = None,
    ):
        self.collector = EKSDataCollector(service)

        self.executor = RuleExecutor(
            handlers=EKS_DATA_SOURCE_HANDLERS,
            rule_parameters=rule_parameters,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=EKS_RULES,
            collector=self.collector,
        )
