from unittest.mock import Mock

from scanner.aws.scanners.cloudformation import (
    CloudFormationScanner,
)


def test_cloudformation_scanner_executes_registry():
    service = Mock()

    scanner = CloudFormationScanner(service)

    scanner.executor.execute_registry = Mock(
        return_value=["finding"]
    )

    assert scanner.scan() == ["finding"]

    scanner.executor.execute_registry.assert_called_once_with(
        registry=__import__(
            "engine.rules.registry.cloudformation_registry",
            fromlist=["CLOUDFORMATION_RULES"],
        ).CLOUDFORMATION_RULES,
        collector=scanner.collector,
    )
