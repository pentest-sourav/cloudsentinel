from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.eventbridge_handlers import (
    EVENTBRIDGE_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.eventbridge_registry import (
    EVENTBRIDGE_RULES,
)

from scanner.aws.collectors.eventbridge import (
    EventBridgeDataCollector,
)
from scanner.aws.services.eventbridge import EventBridgeService


class EventBridgeScanner:
    """
    Runs registered EventBridge security rules.
    """

    def __init__(self, service: EventBridgeService):
        self.collector = EventBridgeDataCollector(service)

        self.executor = RuleExecutor(
            handlers=EVENTBRIDGE_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=EVENTBRIDGE_RULES,
            collector=self.collector,
        )
