from unittest.mock import Mock

from scanner.aws.scanners.guardduty import (
    GuardDutyScanner,
)


def test_scan_executes_guardduty_registry():
    service = Mock()

    scanner = GuardDutyScanner(service)

    executor = Mock()

    executor.execute_registry.return_value = [
        Mock(
            rule_id="CS-AWS-GD-001"
        )
    ]

    scanner.executor = executor

    result = scanner.scan()

    assert len(result) == 1

    executor.execute_registry.assert_called_once()
