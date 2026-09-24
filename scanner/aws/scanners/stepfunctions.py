from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.stepfunctions_handlers import (
    STEPFUNCTIONS_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.stepfunctions_registry import (
    STEPFUNCTIONS_RULES,
)

from scanner.aws.collectors.stepfunctions import (
    StepFunctionsDataCollector,
)
from scanner.aws.services.stepfunctions import StepFunctionsService


class StepFunctionsScanner:
    """
    Runs registered Step Functions security rules.
    """

    def __init__(self, service: StepFunctionsService):
        self.collector = StepFunctionsDataCollector(service)

        self.executor = RuleExecutor(
            handlers=STEPFUNCTIONS_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=STEPFUNCTIONS_RULES,
            collector=self.collector,
        )
