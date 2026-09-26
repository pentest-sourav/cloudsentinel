from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.appconfig_handlers import (
    APPCONFIG_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.appconfig_registry import (
    APPCONFIG_RULES,
)
from scanner.aws.collectors.appconfig import (
    AppConfigDataCollector,
)
from scanner.aws.services.appconfig import (
    AppConfigService,
)


class AppConfigScanner:
    """Runs registered AWS AppConfig security rules."""

    def __init__(self, service: AppConfigService):
        self.collector = AppConfigDataCollector(service)

        self.executor = RuleExecutor(
            handlers=APPCONFIG_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=APPCONFIG_RULES,
            collector=self.collector,
        )
