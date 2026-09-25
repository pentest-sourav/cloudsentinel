from unittest.mock import Mock, patch

from scanner.aws.scanners.kinesis import KinesisScanner


def test_kinesis_scanner_executes_registered_rules():
    service = Mock()

    with patch(
        "scanner.aws.scanners.kinesis.RuleExecutor.execute_registry",
        return_value=[],
    ) as execute_registry:
        scanner = KinesisScanner(service)

        result = scanner.scan()

    assert result == []
    execute_registry.assert_called_once()
