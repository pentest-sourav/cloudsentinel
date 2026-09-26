from unittest.mock import Mock

from scanner.aws.scanners.glue import GlueScanner


def test_glue_scanner_returns_rule_findings():
    service = Mock()

    scanner = GlueScanner(service)

    finding = Mock(rule_id="CS-AWS-GLUE-001")

    scanner.executor.execute_registry = Mock(
        return_value=[finding]
    )

    result = scanner.scan()

    assert result == [finding]
    scanner.executor.execute_registry.assert_called_once()
