from unittest.mock import Mock

from scanner.aws.scanners.network_firewall import (
    NetworkFirewallScanner,
)


def test_scanner_delegates_to_rule_executor():
    service = Mock()
    scanner = NetworkFirewallScanner(service)

    expected = [
        Mock(rule_id="CS-AWS-NETWORKFIREWALL-001")
    ]

    scanner.executor.execute_registry = Mock(
        return_value=expected
    )

    result = scanner.scan()

    assert result == expected
    scanner.executor.execute_registry.assert_called_once()
