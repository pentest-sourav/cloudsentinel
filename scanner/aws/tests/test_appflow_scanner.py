from unittest.mock import Mock

from scanner.aws.scanners.appflow import AppFlowScanner


def test_appflow_scanner_executes_registry():
    service = Mock()

    scanner = AppFlowScanner(service)

    scanner.executor.execute_registry = Mock(
        return_value=["finding"]
    )

    assert scanner.scan() == ["finding"]

    scanner.executor.execute_registry.assert_called_once_with(
        registry=__import__(
            "engine.rules.registry.appflow_registry",
            fromlist=["APPFLOW_RULES"],
        ).APPFLOW_RULES,
        collector=scanner.collector,
    )
