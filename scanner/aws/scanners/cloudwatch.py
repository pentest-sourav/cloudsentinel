from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.cloudwatch_handlers import (
    CLOUDWATCH_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.cloudwatch_registry import (
    CLOUDWATCH_RULES,
)

from scanner.aws.collectors.cloudwatch import (
    CloudWatchDataCollector,
)
from scanner.aws.services.cloudwatch import (
    CloudWatchService,
)


class CloudWatchScanner:
    """
    Runs registered Amazon CloudWatch security rules.
    """

    def __init__(
        self,
        service: CloudWatchService,
    ):
        self.collector = CloudWatchDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=CLOUDWATCH_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=CLOUDWATCH_RULES,
            collector=self.collector,
        )
