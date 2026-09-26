from unittest.mock import Mock

from scanner.aws.scanners.apprunner import (
    AppRunnerScanner,
)


def test_apprunner_scanner_executes_registry():
    service = Mock()

    scanner = AppRunnerScanner(service)

    scanner.executor.execute_registry = Mock(
        return_value=["finding"]
    )

    assert scanner.scan() == ["finding"]

    scanner.executor.execute_registry.assert_called_once_with(
        registry=__import__(
            "engine.rules.registry.apprunner_registry",
            fromlist=["APPRUNNER_RULES"],
        ).APPRUNNER_RULES,
        collector=scanner.collector,
    )
