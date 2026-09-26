from unittest.mock import Mock

from scanner.aws.scanners.appconfig import (
    AppConfigScanner,
)


def test_appconfig_scanner_executes_registry():
    service = Mock()

    scanner = AppConfigScanner(service)

    scanner.executor.execute_registry = Mock(
        return_value=["finding"]
    )

    assert scanner.scan() == ["finding"]

    scanner.executor.execute_registry.assert_called_once_with(
        registry=__import__(
            "engine.rules.registry.appconfig_registry",
            fromlist=["APPCONFIG_RULES"],
        ).APPCONFIG_RULES,
        collector=scanner.collector,
    )
