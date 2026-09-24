from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.dynamodb_handlers import (
    DYNAMODB_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.dynamodb_registry import DYNAMODB_RULES

from scanner.aws.collectors.dynamodb import DynamoDBDataCollector
from scanner.aws.services.dynamodb import DynamoDBService


class DynamoDBScanner:
    """
    Runs registered DynamoDB security rules against AWS
    DynamoDB tables and DAX clusters.
    """

    def __init__(self, service: DynamoDBService):
        self.collector = DynamoDBDataCollector(service)

        self.executor = RuleExecutor(
            handlers=DYNAMODB_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=DYNAMODB_RULES,
            collector=self.collector,
        )
