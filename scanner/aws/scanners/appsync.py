from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.appsync_handlers import (
    APPSYNC_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.appsync_registry import (
    APPSYNC_RULES,
)
from scanner.aws.collectors.appsync import (
    AppSyncDataCollector,
)
from scanner.aws.services.appsync import AppSyncService


class AppSyncScanner:
    """
    Runs registered AWS AppSync security rules.
    """

    def __init__(self, service: AppSyncService):
        self.collector = AppSyncDataCollector(service)

        self.executor = RuleExecutor(
            handlers=APPSYNC_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=APPSYNC_RULES,
            collector=self.collector,
        )
