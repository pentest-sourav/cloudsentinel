from engine.rules.executor import RuleExecutor
from engine.rules.registry.vpc_handlers import VPC_DATA_SOURCE_HANDLERS
from engine.rules.registry.vpc_registry import VPC_RULES
from scanner.aws.collectors.vpc import VPCDataCollector
from scanner.aws.services.vpc import VPCService


class VPCScanner:
    """
    AWS VPC security scanner.

    Collects VPC configuration data and evaluates
    registered VPC security rules.
    """

    def __init__(self, service: VPCService):
        self.collector = VPCDataCollector(service)
        self.executor = RuleExecutor(
            handlers=VPC_DATA_SOURCE_HANDLERS
        )

    def scan(self) -> list:
        return self.executor.execute_registry(
            registry=VPC_RULES,
            collector=self.collector,
        )
