from engine.rules.executor import RuleExecutor
from engine.rules.registry.security_group_handlers import (
    SECURITY_GROUP_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.security_group_registry import (
    SECURITY_GROUP_RULES,
)
from scanner.aws.collectors.security_groups import (
    SecurityGroupDataCollector,
)
from scanner.aws.services.security_groups import (
    SecurityGroupService,
)


class SecurityGroupScanner:
    """
    AWS Security Group security scanner.

    Collects Security Group configuration data and evaluates
    registered Security Group security rules.
    """

    def __init__(self, service: SecurityGroupService):
        self.collector = SecurityGroupDataCollector(service)
        self.executor = RuleExecutor(
            handlers=SECURITY_GROUP_DATA_SOURCE_HANDLERS
        )

    def scan(self) -> list:
        return self.executor.execute_registry(
            registry=SECURITY_GROUP_RULES,
            collector=self.collector,
        )
