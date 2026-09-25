from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.api_gateway_handlers import (
    APIGATEWAY_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.api_gateway_registry import (
    APIGATEWAY_RULES,
)

from scanner.aws.collectors.api_gateway import (
    APIGatewayDataCollector,
)
from scanner.aws.services.api_gateway import APIGatewayService


class APIGatewayScanner:
    """
    Runs all registered Amazon API Gateway security rules.
    """

    def __init__(self, service: APIGatewayService):
        self.collector = APIGatewayDataCollector(service)

        self.executor = RuleExecutor(
            handlers=APIGATEWAY_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=APIGATEWAY_RULES,
            collector=self.collector,
        )
