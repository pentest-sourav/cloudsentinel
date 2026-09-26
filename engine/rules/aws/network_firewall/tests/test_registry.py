from engine.rules.registry.network_firewall_handlers import (
    NETWORK_FIREWALL_DATA_SOURCE_HANDLERS,
)
from engine.rules.registry.network_firewall_registry import (
    NETWORK_FIREWALL_RULES,
)


def test_network_firewall_registry_contains_expected_rules():
    rule_ids = [
        rule.rule_id
        for rule in NETWORK_FIREWALL_RULES.rules
    ]

    assert rule_ids == [
        "CS-AWS-NETWORKFIREWALL-001",
        "CS-AWS-NETWORKFIREWALL-002",
        "CS-AWS-NETWORKFIREWALL-003",
        "CS-AWS-NETWORKFIREWALL-004",
        "CS-AWS-NETWORKFIREWALL-005",
        "CS-AWS-NETWORKFIREWALL-006",
        "CS-AWS-NETWORKFIREWALL-009",
        "CS-AWS-NETWORKFIREWALL-010",
    ]


def test_network_firewall_handlers_cover_all_data_sources():
    assert set(
        NETWORK_FIREWALL_DATA_SOURCE_HANDLERS
    ) == {
        "network_firewalls",
        "network_firewall_policies",
        "network_firewall_stateless_rule_groups",
    }
