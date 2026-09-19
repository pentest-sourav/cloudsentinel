from scanner.aws.collectors.route_tables import RouteTableDataCollector
from scanner.aws.services.route_tables import RouteTableService

from engine.rules.aws.route_tables.handlers import (
    ROUTE_TABLE_DATA_SOURCE_HANDLERS,
)
from engine.rules.aws.route_tables.registry import ROUTE_TABLE_RULES
from engine.rules.executor import RuleExecutor


class RouteTableScanner:
    """
    Scans AWS Route Tables using registered security rules.
    """

    def __init__(self, service: RouteTableService):
        self.collector = RouteTableDataCollector(service)

        self.executor = RuleExecutor(
            handlers=ROUTE_TABLE_DATA_SOURCE_HANDLERS
        )

    def scan(self) -> list:
        return self.executor.execute_registry(
            registry=ROUTE_TABLE_RULES,
            collector=self.collector,
        )
