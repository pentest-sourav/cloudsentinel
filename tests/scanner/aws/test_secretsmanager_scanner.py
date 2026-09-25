from unittest.mock import Mock

from scanner.aws.scanners.secretsmanager import (
    SecretsManagerScanner,
)


def test_scan_executes_secretsmanager_registry():
    service = Mock()

    scanner = SecretsManagerScanner(service)

    executor = Mock()
    executor.execute_registry.return_value = [
        Mock(
            rule_id="CS-AWS-SECRETSMANAGER-001"
        )
    ]

    scanner.executor = executor

    result = scanner.scan()

    assert len(result) == 1

    executor.execute_registry.assert_called_once()
