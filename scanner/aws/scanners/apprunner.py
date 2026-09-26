from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.apprunner_handlers import (
    APPRUNNER_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.apprunner_registry import (
    APPRUNNER_RULES,
)
from scanner.aws.collectors.apprunner import (
    AppRunnerDataCollector,
)
from scanner.aws.services.apprunner import (
    AppRunnerService,
)


class AppRunnerScanner:
    """Runs registered AWS App Runner security rules."""

    def __init__(self, service: AppRunnerService):
        self.collector = AppRunnerDataCollector(service)

        self.executor = RuleExecutor(
            handlers=APPRUNNER_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=APPRUNNER_RULES,
            collector=self.collector,
        )
