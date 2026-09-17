from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.ec2_handlers import (
    EC2_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.ec2_registry import EC2_RULES

from scanner.aws.collectors.ec2 import EC2DataCollector
from scanner.aws.services.ec2 import EC2Service


class EC2Scanner:
    """
    Runs registered EC2 security rules against AWS data.

    AWS collection, rule execution, and finding generation
    remain separated through the existing CloudSentinel
    architecture.
    """

    def __init__(self, service: EC2Service):
        self.collector = EC2DataCollector(service)

        self.executor = RuleExecutor(
            handlers=EC2_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=EC2_RULES,
            collector=self.collector,
        )
