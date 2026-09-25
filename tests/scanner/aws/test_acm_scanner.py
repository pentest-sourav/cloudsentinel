from unittest.mock import Mock

from scanner.aws.scanners.acm import ACMScanner


def test_scan_executes_acm_registry():
    service = Mock()

    scanner = ACMScanner(service)

    executor = Mock()

    executor.execute_registry.return_value = [
        Mock(
            rule_id="CS-AWS-ACM-001"
        )
    ]

    scanner.executor = executor

    result = scanner.scan()

    assert len(result) == 1

    executor.execute_registry.assert_called_once()
