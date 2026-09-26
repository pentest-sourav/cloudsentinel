from unittest.mock import Mock

from scanner.aws.collectors.network_firewall import (
    NetworkFirewallDataCollector,
)


def test_collect_firewalls_normalizes_security_fields():
    service = Mock()

    service.list_firewalls.return_value = [
        {
            "FirewallArn": "arn:aws:network-firewall:region:123:firewall/prod",
            "FirewallName": "prod",
        }
    ]

    service.describe_firewall.return_value = {
        "FirewallArn": (
            "arn:aws:network-firewall:region:123:"
            "firewall/prod"
        ),
        "FirewallPolicyArn": "arn:policy:prod",
        "VpcId": "vpc-123",
        "AvailabilityZoneMappings": [
            {"AvailabilityZone": "ap-south-1a"},
            {"AvailabilityZone": "ap-south-1b"},
        ],
        "SubnetMappings": [
            {"SubnetId": "subnet-1"},
            {"SubnetId": "subnet-2"},
        ],
        "DeleteProtection": True,
        "SubnetChangeProtection": True,
    }

    service.describe_logging_configuration.return_value = {
        "LogDestinationConfigs": [
            {
                "LogType": "ALERT",
                "LogDestinationType": "CloudWatchLogs",
                "LogDestination": {
                    "logGroup": "/aws/network-firewall/prod"
                },
            }
        ]
    }

    collector = NetworkFirewallDataCollector(service)

    assert collector.collect_firewalls() == [
        {
            "resource_id": (
                "arn:aws:network-firewall:region:123:"
                "firewall/prod"
            ),
            "resource_type": "network_firewall",
            "resource_arn": (
                "arn:aws:network-firewall:region:123:"
                "firewall/prod"
            ),
            "firewall_name": "prod",
            "firewall_policy_arn": "arn:policy:prod",
            "vpc_id": "vpc-123",
            "availability_zones": [
                "ap-south-1a",
                "ap-south-1b",
            ],
            "availability_zone_count": 2,
            "subnet_mappings": [
                {"SubnetId": "subnet-1"},
                {"SubnetId": "subnet-2"},
            ],
            "delete_protection": True,
            "subnet_change_protection": True,
            "logging_enabled": True,
            "log_destination_count": 1,
        }
    ]


def test_collect_firewalls_uses_subnet_mapping_count_without_fake_az_names():
    service = Mock()

    service.list_firewalls.return_value = [
        {
            "FirewallArn": "arn:fw:1",
            "FirewallName": "prod",
        }
    ]

    service.describe_firewall.return_value = {
        "FirewallArn": "arn:fw:1",
        "SubnetMappings": [
            {"SubnetId": "subnet-1"},
            {"SubnetId": "subnet-2"},
        ],
    }

    service.describe_logging_configuration.return_value = {}

    result = NetworkFirewallDataCollector(
        service
    ).collect_firewalls()

    assert result[0]["availability_zones"] == []
    assert result[0]["availability_zone_count"] == 2


def test_collect_firewall_policies_normalizes_rule_groups_and_actions():
    service = Mock()

    service.list_firewall_policies.return_value = [
        {
            "Arn": "arn:policy:1",
            "Name": "prod-policy",
        }
    ]

    service.describe_firewall_policy.return_value = {
        "Arn": "arn:policy:1",
        "StatelessRuleGroupReferences": [
            {"ResourceArn": "arn:stateless:1"}
        ],
        "StatefulRuleGroupReferences": [
            {"ResourceArn": "arn:stateful:1"}
        ],
        "StatelessDefaultActions": ["aws:drop"],
        "StatelessFragmentDefaultActions": [
            "aws:forward_to_sfe"
        ],
    }

    result = NetworkFirewallDataCollector(
        service
    ).collect_firewall_policies()

    assert result == [
        {
            "resource_id": "arn:policy:1",
            "resource_type": "network_firewall_policy",
            "resource_arn": "arn:policy:1",
            "policy_name": "prod-policy",
            "stateless_rule_group_count": 1,
            "stateful_rule_group_count": 1,
            "has_rule_group": True,
            "stateless_default_actions": ["aws:drop"],
            "stateless_fragment_default_actions": [
                "aws:forward_to_sfe"
            ],
        }
    ]


def test_collect_stateless_rule_groups_counts_rules():
    service = Mock()

    service.list_stateless_rule_groups.return_value = [
        {
            "Arn": "arn:group:1",
            "Name": "prod-stateless",
        }
    ]

    service.describe_rule_group.return_value = {
        "RuleGroup": {
            "RulesSource": {
                "StatelessRulesAndCustomActions": {
                    "StatelessRules": [
                        {"RuleDefinition": {}},
                        {"RuleDefinition": {}},
                    ]
                }
            }
        },
        "RuleGroupResponse": {},
    }

    result = NetworkFirewallDataCollector(
        service
    ).collect_stateless_rule_groups()

    assert result == [
        {
            "resource_id": "arn:group:1",
            "resource_type": (
                "network_firewall_stateless_rule_group"
            ),
            "resource_arn": "arn:group:1",
            "rule_group_name": "prod-stateless",
            "rule_group_type": "STATELESS",
            "stateless_rule_count": 2,
        }
    ]


def test_collector_caches_all_nested_resources():
    service = Mock()

    service.list_firewalls.return_value = [
        {
            "FirewallArn": "arn:fw:1",
            "FirewallName": "prod",
        }
    ]

    service.describe_firewall.return_value = {
        "FirewallArn": "arn:fw:1",
        "AvailabilityZoneMappings": [],
        "SubnetMappings": [],
    }

    service.describe_logging_configuration.return_value = {}

    collector = NetworkFirewallDataCollector(service)

    collector.collect_firewalls()
    collector.collect_firewalls()

    service.list_firewalls.assert_called_once()
    service.describe_firewall.assert_called_once_with(
        "arn:fw:1"
    )
    service.describe_logging_configuration.assert_called_once_with(
        "arn:fw:1"
    )
