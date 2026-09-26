from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.config_handlers import (
    CONFIG_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.config_registry import CONFIG_RULES
from scanner.aws.collectors.config import ConfigDataCollector
from scanner.aws.services.config import ConfigService


class ConfigScanner:
    """Runs registered AWS Config security rules."""

    def __init__(self, service: ConfigService):
        self.collector = ConfigDataCollector(service)

        self.executor = RuleExecutor(
            handlers=CONFIG_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=CONFIG_RULES,
            collector=self.collector,
        )
