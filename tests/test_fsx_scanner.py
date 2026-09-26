from unittest.mock import Mock, patch

from scanner.aws.scanners.fsx import FSxScanner


def test_fsx_scanner_executes_registry():
    service = Mock()

    with patch(
        "scanner.aws.scanners.fsx.RuleExecutor.execute_registry",
        return_value=[],
    ) as execute_registry:
        scanner = FSxScanner(service)

        result = scanner.scan()

    assert result == []
    execute_registry.assert_called_once()
    assert execute_registry.call_args.kwargs["registry"] is not None
    assert execute_registry.call_args.kwargs["collector"] is scanner.collector
