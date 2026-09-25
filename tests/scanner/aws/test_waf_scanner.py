from unittest.mock import Mock

from scanner.aws.scanners.waf import WAFScanner


def test_scan_executes_waf_registry():
    service = Mock()
    collector = Mock()
    executor = Mock()

    scanner = WAFScanner(service)

    scanner.collector = collector
    scanner.executor = executor

    executor.execute_registry.return_value = [
        Mock(rule_id="CS-AWS-WAF-010")
    ]

    result = scanner.scan()

    assert len(result) == 1

    executor.execute_registry.assert_called_once()
