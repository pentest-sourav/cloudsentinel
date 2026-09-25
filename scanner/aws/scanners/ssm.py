
from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.ssm_handlers import (
    SSM_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.ssm_registry import SSM_RULES

from scanner.aws.collectors.ssm import SSMDataCollector
from scanner.aws.services.ssm import SSMService


class SSMScanner:
    """
    Runs registered AWS Systems Manager security rules.
    """

    def __init__(
        self,
        service: SSMService,
    ):
        self.collector = SSMDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=SSM_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=SSM_RULES,
            collector=self.collector,
        )

