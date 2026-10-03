from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.ecr_handlers import (
    ECR_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.ecr_registry import ECR_RULES

from scanner.aws.collectors.ecr import ECRDataCollector
from scanner.aws.services.ecr import ECRService


class ECRScanner:
    """
    Runs registered ECR security rules against AWS ECR repositories.
    """

    def __init__(
        self,
        service: ECRService,
        rule_parameters: dict[str, dict[str, object]] | None = None,
    ):
        self.collector = ECRDataCollector(service)

        self.executor = RuleExecutor(
            handlers=ECR_DATA_SOURCE_HANDLERS,
            rule_parameters=rule_parameters,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=ECR_RULES,
            collector=self.collector,
        )
