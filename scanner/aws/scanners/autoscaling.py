from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.autoscaling_handlers import (
    AUTOSCALING_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.autoscaling_registry import (
    AUTOSCALING_RULES,
)
from scanner.aws.collectors.autoscaling import (
    AutoScalingDataCollector,
)
from scanner.aws.services.autoscaling import AutoScalingService


class AutoScalingScanner:
    """Runs registered AWS EC2 Auto Scaling security rules."""

    def __init__(
        self,
        service: AutoScalingService,
    ):
        self.collector = AutoScalingDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=AUTOSCALING_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=AUTOSCALING_RULES,
            collector=self.collector,
        )
