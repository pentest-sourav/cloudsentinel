from unittest.mock import Mock, patch

from scanner.aws.scanners.ssm import SSMScanner


@patch(
    "scanner.aws.scanners.ssm.SSMDataCollector"
)
def test_ssm_scanner_executes_registry(
    collector_class,
):
    service = Mock()

    collector = collector_class.return_value

    executor = Mock()
    executor.execute_registry.return_value = []

    with patch(
        "scanner.aws.scanners.ssm.RuleExecutor",
        return_value=executor,
    ):
        scanner = SSMScanner(service)

    assert scanner.collector is collector

    result = scanner.scan()

    assert result == []

    executor.execute_registry.assert_called_once()
