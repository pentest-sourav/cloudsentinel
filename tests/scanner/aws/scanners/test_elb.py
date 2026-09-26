from unittest.mock import Mock

from scanner.aws.scanners.elb import ELBScanner


def test_elb_scanner_executes_registry():
    service = Mock()

    service.list_classic_load_balancers.return_value = []
    service.list_load_balancers.return_value = []

    scanner = ELBScanner(service)

    findings = scanner.scan()

    assert findings == []
    service.list_classic_load_balancers.assert_called_once()
    service.list_load_balancers.assert_called_once()
