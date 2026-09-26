from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.amplify_handlers import (
    AMPLIFY_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.amplify_registry import (
    AMPLIFY_RULES,
)
from scanner.aws.collectors.amplify import (
    AmplifyDataCollector,
)
from scanner.aws.services.amplify import (
    AmplifyService,
)


class AmplifyScanner:
    """Runs registered AWS Amplify security rules."""

    def __init__(self, service: AmplifyService):
        self.collector = AmplifyDataCollector(service)

        self.executor = RuleExecutor(
            handlers=AMPLIFY_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=AMPLIFY_RULES,
            collector=self.collector,
        )
