from unittest.mock import Mock, patch

from scanner.aws.scanners.securityhub import (
    SecurityHubScanner,
)


def test_securityhub_scanner_executes_registered_rules():
    service = Mock()

    with patch(
        "scanner.aws.scanners.securityhub.RuleExecutor.execute_registry",
        return_value=[],
    ) as execute_registry:
        scanner = SecurityHubScanner(service)

        result = scanner.scan()

    assert result == []
    execute_registry.assert_called_once()
    assert execute_registry.call_args.kwargs[
        "registry"
    ].list_rules()
