from unittest.mock import Mock

from scanner.aws.scanners.ecs import ECSScanner


def test_ecs_scanner_runs_registry():
    service = Mock()

    service.list_clusters.return_value = []
    service.describe_clusters.return_value = []
    service.list_task_definitions.return_value = []
    service.describe_task_definitions.return_value = []
    service.list_capacity_providers.return_value = []
    service.describe_capacity_providers.return_value = []

    scanner = ECSScanner(service)

    findings = scanner.scan()

    assert findings == []

    service.list_clusters.assert_called_once()
    service.list_task_definitions.assert_called_once()
    service.list_capacity_providers.assert_called_once()
