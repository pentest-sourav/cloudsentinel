from unittest.mock import Mock

from scanner.aws.scanners.emr import EMRScanner


def test_emr_scanner_returns_rule_findings():
    service = Mock()

    scanner = EMRScanner(service)

    finding = Mock(rule_id="CS-AWS-EMR-001")
    scanner.executor.execute_registry = Mock(
        return_value=[finding]
    )

    result = scanner.scan()

    assert result == [finding]
    scanner.executor.execute_registry.assert_called_once()
