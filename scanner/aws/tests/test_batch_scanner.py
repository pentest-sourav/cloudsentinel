from unittest.mock import Mock

from scanner.aws.scanners.batch import BatchScanner


def test_batch_scanner_executes_registered_rules():
    service = Mock()

    service.describe_job_queues.return_value = []
    service.list_scheduling_policies.return_value = []
    service.describe_scheduling_policies.return_value = []
    service.describe_compute_environments.return_value = []

    scanner = BatchScanner(service)

    assert scanner.scan() == []
