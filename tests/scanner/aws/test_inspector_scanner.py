from unittest.mock import Mock

from scanner.aws.scanners.inspector import (
    InspectorScanner,
)


def test_inspector_scanner_executes_registered_rules():
    service = Mock()

    service.get_account_status.return_value = {
        "account_id": "123456789012",
        "account_status": "ENABLED",
        "ec2_status": "DISABLED",
        "ecr_status": "ENABLED",
        "lambda_status": "ENABLED",
        "lambda_code_status": "DISABLED",
    }

    scanner = InspectorScanner(service)

    findings = scanner.scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-INSPECTOR-001",
        "CS-AWS-INSPECTOR-003",
    }
