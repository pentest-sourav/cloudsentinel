from unittest.mock import Mock, patch

from scanner.aws.scanners.eventbridge import (
    EventBridgeScanner,
)


def test_eventbridge_scanner_executes_registered_rules():
    service = Mock()

    with patch(
        "scanner.aws.scanners.eventbridge."
        "RuleExecutor.execute_registry",
        return_value=[],
    ) as execute_registry:
        scanner = EventBridgeScanner(service)

        result = scanner.scan()

    assert result == []
    execute_registry.assert_called_once()
