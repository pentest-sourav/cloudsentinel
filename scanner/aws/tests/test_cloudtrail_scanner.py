from unittest.mock import Mock, patch

from scanner.aws.scanners.cloudtrail_scanner import CloudTrailScanner


def test_cloudtrail_scanner_initializes_correctly():
    service = Mock()

    scanner = CloudTrailScanner(service)

    assert scanner.collector is not None
    assert scanner.executor is not None


@patch(
    "scanner.aws.scanners.cloudtrail_scanner.RuleExecutor.execute_registry"
)
def test_cloudtrail_scanner_executes_cloudtrail_registry(
    mock_execute_registry,
):
    service = Mock()

    expected_findings = [
        Mock(rule_id="CS-AWS-CT-001"),
        Mock(rule_id="CS-AWS-CT-002"),
    ]

    mock_execute_registry.return_value = expected_findings

    scanner = CloudTrailScanner(service)

    findings = scanner.scan()

    assert findings == expected_findings

    mock_execute_registry.assert_called_once()

    call_kwargs = mock_execute_registry.call_args.kwargs

    assert call_kwargs["registry"] is not None
    assert call_kwargs["collector"] is scanner.collector
