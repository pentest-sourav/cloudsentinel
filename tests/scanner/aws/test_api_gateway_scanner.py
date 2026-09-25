from unittest.mock import Mock, patch

from scanner.aws.scanners.api_gateway import (
    APIGatewayScanner,
)


def test_api_gateway_scanner_executes_registry():
    service = Mock()

    with patch(
        "scanner.aws.scanners.api_gateway.APIGatewayDataCollector"
    ) as collector_cls, patch(
        "scanner.aws.scanners.api_gateway.RuleExecutor"
    ) as executor_cls:
        collector = collector_cls.return_value
        executor = executor_cls.return_value

        executor.execute_registry.return_value = []

        scanner = APIGatewayScanner(service)

        result = scanner.scan()

    collector_cls.assert_called_once_with(service)

    executor_cls.assert_called_once()

    executor.execute_registry.assert_called_once()

    assert result == []
