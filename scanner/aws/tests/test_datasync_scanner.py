from unittest.mock import Mock

from scanner.aws.scanners.datasync import (
    DataSyncScanner,
)


def test_datasync_scanner_runs_registered_rules():
    service = Mock()

    service.list_tasks.return_value = []

    scanner = DataSyncScanner(service)

    assert scanner.scan() == []
