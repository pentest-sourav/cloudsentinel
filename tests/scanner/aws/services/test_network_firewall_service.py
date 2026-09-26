from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.network_firewall import (
    NetworkFirewallService,
)


def make_service():
    session = Mock()
    client = Mock()
    session.client.return_value = client

    service = NetworkFirewallService(session)

    return service, client


def test_list_firewalls_paginates():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {"Firewalls": [{"FirewallArn": "arn:fw:1"}]},
        {"Firewalls": [{"FirewallArn": "arn:fw:2"}]},
    ]
    client.get_paginator.return_value = paginator

    assert service.list_firewalls() == [
        {"FirewallArn": "arn:fw:1"},
        {"FirewallArn": "arn:fw:2"},
    ]

    client.get_paginator.assert_called_once_with(
        "list_firewalls"
    )


def test_describe_firewall_returns_firewall():
    service, client = make_service()

    client.describe_firewall.return_value = {
        "Firewall": {
            "FirewallArn": "arn:fw:1",
            "FirewallName": "prod-firewall",
        }
    }

    assert service.describe_firewall("arn:fw:1") == {
        "FirewallArn": "arn:fw:1",
        "FirewallName": "prod-firewall",
    }

    client.describe_firewall.assert_called_once_with(
        FirewallArn="arn:fw:1"
    )


def test_list_firewall_policies_paginates():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {"FirewallPolicies": [{"Arn": "arn:policy:1"}]},
        {"FirewallPolicies": [{"Arn": "arn:policy:2"}]},
    ]
    client.get_paginator.return_value = paginator

    assert service.list_firewall_policies() == [
        {"Arn": "arn:policy:1"},
        {"Arn": "arn:policy:2"},
    ]

    client.get_paginator.assert_called_once_with(
        "list_firewall_policies"
    )


def test_describe_firewall_policy_returns_policy():
    service, client = make_service()

    client.describe_firewall_policy.return_value = {
        "FirewallPolicy": {
            "Arn": "arn:policy:1",
            "StatelessDefaultActions": [
                "aws:drop"
            ],
        }
    }

    assert service.describe_firewall_policy(
        "arn:policy:1"
    ) == {
        "Arn": "arn:policy:1",
        "StatelessDefaultActions": ["aws:drop"],
    }


def test_list_stateless_rule_groups_uses_account_scope_and_stateless_type():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "RuleGroups": [
                {
                    "Arn": "arn:group:1",
                    "Name": "stateless-rules",
                }
            ]
        }
    ]
    client.get_paginator.return_value = paginator

    assert service.list_stateless_rule_groups() == [
        {
            "Arn": "arn:group:1",
            "Name": "stateless-rules",
        }
    ]

    paginator.paginate.assert_called_once_with(
        Scope="ACCOUNT",
        Type="STATELESS",
    )


def test_describe_rule_group_returns_both_response_sections():
    service, client = make_service()

    client.describe_rule_group.return_value = {
        "RuleGroup": {"RulesSource": {}},
        "RuleGroupResponse": {"RuleGroupArn": "arn:group:1"},
    }

    assert service.describe_rule_group(
        "arn:group:1"
    ) == {
        "RuleGroup": {"RulesSource": {}},
        "RuleGroupResponse": {
            "RuleGroupArn": "arn:group:1"
        },
    }

    client.describe_rule_group.assert_called_once_with(
        RuleGroupArn="arn:group:1",
        Type="STATELESS",
    )


def test_missing_logging_configuration_returns_empty_dict():
    service, client = make_service()

    client.describe_logging_configuration.side_effect = (
        ClientError(
            {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": "No logging configuration",
                }
            },
            "DescribeLoggingConfiguration",
        )
    )

    assert service.describe_logging_configuration(
        "arn:fw:1"
    ) == {}


def test_service_wraps_client_error():
    service, client = make_service()

    client.describe_firewall.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "Access denied",
            }
        },
        "DescribeFirewall",
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "Network Firewall firewall lookup for "
            "arn:fw:1 failed"
        ),
    ):
        service.describe_firewall("arn:fw:1")
