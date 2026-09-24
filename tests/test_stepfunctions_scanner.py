from unittest.mock import Mock, patch

from scanner.aws.scanners.stepfunctions import (
    StepFunctionsScanner,
)


def test_stepfunctions_scanner_executes_registered_rules():
    service = Mock()

    with patch(
        "scanner.aws.scanners.stepfunctions."
        "RuleExecutor.execute_registry",
        return_value=[],
    ) as execute_registry:
        scanner = StepFunctionsScanner(service)

        result = scanner.scan()

    assert result == []
    execute_registry.assert_called_once()
