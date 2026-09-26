from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.appflow_handlers import (
    APPFLOW_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.appflow_registry import APPFLOW_RULES

from scanner.aws.collectors.appflow import AppFlowDataCollector
from scanner.aws.services.appflow import AppFlowService


class AppFlowScanner:
    """
    Run registered Amazon AppFlow security rules.
    """

    def __init__(self, service: AppFlowService):
        self.collector = AppFlowDataCollector(service)

        self.executor = RuleExecutor(
            handlers=APPFLOW_DATA_SOURCE_HANDLERS,
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=APPFLOW_RULES,
            collector=self.collector,
        )
