from unittest.mock import Mock, patch

from scanner.aws.scanners.macie import MacieScanner


def test_macie_scanner_executes_registered_rules():
    service = Mock()

    service.get_macie_session.return_value = {
        "status": "PAUSED",
        "accountId": "123456789012",
    }

    service.get_administrator_account.return_value = None

    service.get_automated_discovery_configuration.return_value = {
        "status": "DISABLED",
    }

    with patch(
        "scanner.aws.scanners.macie.RuleExecutor.execute_registry",
        return_value=[],
    ) as execute_registry:
        scanner = MacieScanner(service)

        result = scanner.scan()

    assert result == []
    execute_registry.assert_called_once()
