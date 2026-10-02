from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.cloudformation_handlers import (
    CLOUDFORMATION_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.cloudformation_registry import (
    CLOUDFORMATION_RULES,
)
from scanner.aws.collectors.cloudformation import (
    CloudFormationDataCollector,
)
from scanner.aws.services.cloudformation import (
    CloudFormationService,
)


class CloudFormationScanner:
    """Runs registered AWS CloudFormation security rules."""

    def __init__(
        self,
        service: CloudFormationService,
        rule_parameters: dict[str, dict[str, object]] | None = None,
    ):
        self.collector = CloudFormationDataCollector(service)

        self.executor = RuleExecutor(
            handlers=CLOUDFORMATION_DATA_SOURCE_HANDLERS,
            rule_parameters=rule_parameters,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=CLOUDFORMATION_RULES,
            collector=self.collector,
        )
