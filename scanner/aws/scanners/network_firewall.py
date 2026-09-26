from engine.findings.model import Finding
from engine.rules.executor import RuleExecutor
from engine.rules.registry.network_firewall_handlers import (
    NETWORK_FIREWALL_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.network_firewall_registry import (
    NETWORK_FIREWALL_RULES,
)

from scanner.aws.collectors.network_firewall import (
    NetworkFirewallDataCollector,
)
from scanner.aws.services.network_firewall import (
    NetworkFirewallService,
)


class NetworkFirewallScanner:
    """
    Runs registered AWS Network Firewall security rules.
    """

    def __init__(
        self,
        service: NetworkFirewallService,
    ):
        self.collector = NetworkFirewallDataCollector(
            service
        )

        self.executor = RuleExecutor(
            handlers=(
                NETWORK_FIREWALL_DATA_SOURCE_HANDLERS
            ),
        )

    def scan(self) -> list[Finding]:
        return self.executor.execute_registry(
            registry=NETWORK_FIREWALL_RULES,
            collector=self.collector,
        )
