from unittest.mock import Mock

from scanner.aws.scanners.eks import EKSScanner


def test_scan_executes_eks_registry():
    service = Mock()
    executor = Mock()

    scanner = EKSScanner(service)

    executor.execute_registry.return_value = [
        Mock(rule_id="CS-AWS-EKS-001")
    ]

    scanner.executor = executor

    result = scanner.scan()

    assert len(result) == 1

    executor.execute_registry.assert_called_once()
