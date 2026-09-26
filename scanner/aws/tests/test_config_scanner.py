from unittest.mock import Mock, patch

from scanner.aws.scanners.config import ConfigScanner


def test_config_scanner_executes_registered_rules():
    service = Mock()

    with patch(
        "scanner.aws.scanners.config.RuleExecutor.execute_registry",
        return_value=[],
    ) as execute_registry:
        scanner = ConfigScanner(service)

        result = scanner.scan()

    assert result == []
    execute_registry.assert_called_once()
    assert execute_registry.call_args.kwargs[
        "registry"
    ].list_rules()
