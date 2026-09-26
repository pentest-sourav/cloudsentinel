from unittest.mock import Mock

from scanner.aws.scanners.detective import (
    DetectiveScanner,
)


def test_detective_scanner_runs_registered_rules():
    service = Mock()
    service.list_graphs.return_value = []

    scanner = DetectiveScanner(service)

    assert scanner.scan() == []
