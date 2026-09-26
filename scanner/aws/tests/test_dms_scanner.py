from unittest.mock import Mock

from scanner.aws.scanners.dms import DMSScanner


def test_dms_scanner_runs_registered_rules():
    service = Mock()

    service.describe_replication_instances.return_value = []
    service.describe_certificates.return_value = []
    service.describe_event_subscriptions.return_value = []
    service.describe_replication_subnet_groups.return_value = []
    service.describe_replication_tasks.return_value = []
    service.describe_endpoints.return_value = []

    scanner = DMSScanner(service)

    assert scanner.scan() == []
