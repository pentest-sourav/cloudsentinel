from unittest.mock import Mock, patch

from scanner.aws.scanners.sqs import SQSScanner


def test_sqs_scanner_executes_registered_rules():
    service = Mock()

    with patch(
        "scanner.aws.scanners.sqs.RuleExecutor.execute_registry",
        return_value=[],
    ) as execute_registry:
        scanner = SQSScanner(service)

        result = scanner.scan()

    assert result == []
    execute_registry.assert_called_once()
