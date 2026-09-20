from unittest.mock import Mock

from scanner.aws.scanners.iam import IAMScanner


def _configure_credential_report(service):
    service.get_credential_report.return_value = {
        "Content": b"user,password_enabled,password_last_used\n",
        "ReportFormat": "text/csv",
    }


def test_iam_scanner_returns_root_and_user_mfa_findings():
    service = Mock()

    service.get_root_mfa_status.return_value = False

    service.list_users.return_value = [
        {"UserName": "user-without-mfa"},
    ]

    service.list_mfa_devices.return_value = []

    service.list_access_keys.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    _configure_credential_report(service)

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
            "SerialNumber": (
                "arn:aws:iam::123456789012:mfa/protected-user"
            )
        }
    ]

    service.list_access_keys.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireLowercaseCharacters": True,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 24,
    }

    _configure_credential_report(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_iam_scanner_uses_registry_data_sources():
    service = Mock()

    service.get_root_mfa_status.return_value = True

    service.list_users.return_value = [
        {"UserName": "test-user"},
    ]

    service.list_mfa_devices.return_value = [
        {
            "SerialNumber": (
                "arn:aws:iam::123456789012:mfa/test-user"
            )
        }
    ]

    service.list_access_keys.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireLowercaseCharacters": True,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 24,
    }

    _configure_credential_report(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    service.get_root_mfa_status.assert_called_once()
    service.list_users.assert_called_once()
    service.list_access_keys.assert_called_once()
    service.get_credential_report.assert_called_once()

    assert findings == []
