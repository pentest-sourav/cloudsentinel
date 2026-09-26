from unittest.mock import Mock, patch

from scanner.aws.scanners.codebuild import (
    CodeBuildScanner,
)


@patch(
    "scanner.aws.scanners.codebuild.CodeBuildDataCollector"
)
def test_codebuild_scanner_executes_registry(
    collector_class,
):
    service = Mock()

    collector = collector_class.return_value

    executor = Mock()
    executor.execute_registry.return_value = []

    with patch(
        "scanner.aws.scanners.codebuild.RuleExecutor",
        return_value=executor,
    ):
        scanner = CodeBuildScanner(service)

    assert scanner.collector is collector

    result = scanner.scan()

    assert result == []

    executor.execute_registry.assert_called_once()
