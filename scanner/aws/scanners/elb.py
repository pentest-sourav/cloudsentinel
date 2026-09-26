from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.elb_handlers import (
    ELB_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.elb_registry import ELB_RULES
from scanner.aws.collectors.elb import ELBDataCollector
from scanner.aws.services.elb import ELBService


class ELBScanner:
    """
    Execute Elastic Load Balancing security posture rules.
    """

    def __init__(
        self,
        service: ELBService,
    ):
        self.collector = ELBDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=ELB_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=ELB_RULES,
            collector=self.collector,
        )
