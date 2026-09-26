from unittest.mock import Mock, patch

from scanner.aws.scanners.athena import (
    AthenaScanner,
)


def test_athena_scanner_executes_registered_rules():
    service = Mock()
    expected = [Mock()]

    with patch(
        "scanner.aws.scanners.athena."
        "RuleExecutor.execute_registry",
        return_value=expected,
    ) as execute:
        scanner = AthenaScanner(service)
        result = scanner.scan()

    assert result == expected
    execute.assert_called_once()

    assert (
        execute.call_args.kwargs["registry"]
    )

    assert (
        execute.call_args.kwargs["collector"]
        is scanner.collector
    )
