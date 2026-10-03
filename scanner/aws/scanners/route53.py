from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.route53_handlers import (
    ROUTE53_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.route53_registry import (
    ROUTE53_RULES,
)

from scanner.aws.collectors.route53 import (
    Route53DataCollector,
)
from scanner.aws.services.route53 import Route53Service


class Route53Scanner:
    """
    Runs registered Amazon Route 53 security rules.
    """

    def __init__(self, service: Route53Service, rule_parameters=None):
        self.collector = Route53DataCollector(service)

        self.executor = RuleExecutor(
            handlers=ROUTE53_DATA_SOURCE_HANDLERS,
            rule_parameters=rule_parameters,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=ROUTE53_RULES,
            collector=self.collector,
        )
