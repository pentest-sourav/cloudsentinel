from scanner.aws.collectors.network_firewall import (
    NetworkFirewallDataCollector,
)


def collect_network_firewalls(
    collector: NetworkFirewallDataCollector,
):
    return collector.collect_firewalls()


def collect_network_firewall_policies(
    collector: NetworkFirewallDataCollector,
):
    return collector.collect_firewall_policies()


def collect_network_firewall_stateless_rule_groups(
    collector: NetworkFirewallDataCollector,
):
    return collector.collect_stateless_rule_groups()


NETWORK_FIREWALL_DATA_SOURCE_HANDLERS = {
    "network_firewalls": collect_network_firewalls,
    "network_firewall_policies": (
        collect_network_firewall_policies
    ),
    "network_firewall_stateless_rule_groups": (
        collect_network_firewall_stateless_rule_groups
    ),
}
