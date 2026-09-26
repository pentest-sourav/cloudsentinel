from unittest.mock import Mock

from scanner.aws.scanners.amplify import (
    AmplifyScanner,
)


def test_amplify_scanner_executes_registry():
    service = Mock()

    scanner = AmplifyScanner(service)

    scanner.executor.execute_registry = Mock(
        return_value=["finding"]
    )

    assert scanner.scan() == ["finding"]

    scanner.executor.execute_registry.assert_called_once_with(
        registry=__import__(
            "engine.rules.registry.amplify_registry",
            fromlist=["AMPLIFY_RULES"],
        ).AMPLIFY_RULES,
        collector=scanner.collector,
    )
