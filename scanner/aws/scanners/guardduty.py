from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.guardduty_handlers import (
    GUARDDUTY_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.guardduty_registry import (
    GUARDDUTY_RULES,
)

from scanner.aws.collectors.guardduty import (
    GuardDutyDataCollector,
)
from scanner.aws.services.guardduty import (
    GuardDutyService,
)


class GuardDutyScanner:
    """
    Runs registered Amazon GuardDuty security rules.
    """

    def __init__(
        self,
        service: GuardDutyService,
    ):
        self.collector = GuardDutyDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=GUARDDUTY_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=GUARDDUTY_RULES,
            collector=self.collector,
        )
