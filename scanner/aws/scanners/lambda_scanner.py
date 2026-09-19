from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.lambda_handlers import (
    LAMBDA_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.lambda_registry import LAMBDA_RULES
from scanner.aws.collectors.lambda_collector import LambdaDataCollector
from scanner.aws.services.lambda_service import LambdaService


class LambdaScanner:
    """
    Runs CloudSentinel security rules against AWS Lambda functions.
    """

    def __init__(self, service: LambdaService):
        self.collector = LambdaDataCollector(service)
        self.executor = RuleExecutor(
            handlers=LAMBDA_DATA_SOURCE_HANDLERS
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=LAMBDA_RULES,
            collector=self.collector,
        )
