from unittest.mock import Mock

from scanner.aws.scanners.iam import IAMScanner


def test_iam_scanner_returns_root_and_user_mfa_findings():
    service = Mock()

    service.get_root_mfa_status.return_value = False
    service.list_users.return_value = [
        {"UserName": "user-without-mfa"},
    ]
    service.list_mfa_devices.return_value = []

    scanner = IAMScanner(service)

    findings = scanner.scan()

    rule_ids = [finding.rule_id for finding in findings]

    assert "CS-AWS-IAM-001" in rule_ids
    assert "CS-AWS-IAM-002" in rule_ids


def test_iam_scanner_returns_no_mfa_findings_when_users_are_protected():
    service = Mock()

    service.get_root_mfa_status.return_value = True
    service.list_users.return_value = [
        {"UserName": "protected-user"},
    ]
    service.list_mfa_devices.return_value = [
        {
            "SerialNumber": "arn:aws:iam::123456789012:mfa/protected-user"
        }
    ]

    scanner = IAMScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_iam_scanner_uses_registry_data_sources():
    service = Mock()

    service.get_root_mfa_status.return_value = True
    service.list_users.return_value = []

    scanner = IAMScanner(service)

    findings = scanner.scan()

    service.get_root_mfa_status.assert_called_once()
    service.list_users.assert_called_once()

    assert findings == []
