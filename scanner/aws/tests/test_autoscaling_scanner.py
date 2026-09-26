from unittest.mock import Mock

from scanner.aws.scanners.autoscaling import (
    AutoScalingScanner,
)


def test_autoscaling_scanner_executes_registered_rules():
    service = Mock()

    service.list_auto_scaling_groups.return_value = []

    scanner = AutoScalingScanner(service)

    assert scanner.scan() == []

    service.list_auto_scaling_groups.assert_called_once()
