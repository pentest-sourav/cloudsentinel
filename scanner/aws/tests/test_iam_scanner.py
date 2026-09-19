from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.aws.scanners.iam import IAMScanner


def test_iam_scanner_detects_old_active_access_key():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_users.return_value = [
        {
            "UserName": "test-user",
        }
    ]

    service.list_mfa_devices.return_value = [
        {
            "SerialNumber": "arn:aws:iam::123456789012:mfa/test-user",
        }
    ]

    service.list_access_keys.return_value = [
        {
            "AccessKeyId": "AKIAOLD123",
            "Status": "Active",
            "CreateDate": datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        }
    ]

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam003_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-003"
    ]

    assert len(iam003_findings) == 1

    finding = iam003_findings[0]

    assert finding.resource_id == "AKIAOLD123"
    assert finding.severity.value == "high"
    assert finding.evidence["username"] == "test-user"
    assert finding.evidence["status"] == "Active"
    assert finding.evidence["threshold_days"] == 90

def test_iam_scanner_detects_short_password_policy():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.list_users.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 8,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam005_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-005"
    ]

    assert len(iam005_findings) == 1

    finding = iam005_findings[0]

    assert finding.resource_id == "account-password-policy"
    assert finding.severity.value == "medium"
    assert finding.evidence["minimum_password_length"] == 8
    assert finding.evidence["threshold"] == 14

    service.get_account_password_policy.assert_called_once_with()

def test_iam_scanner_detects_password_policy_without_symbols():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.list_users.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": False,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam006_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-006"
    ]

    assert len(iam006_findings) == 1

    finding = iam006_findings[0]

    assert finding.resource_id == "account-password-policy"
    assert finding.severity.value == "medium"
    assert finding.evidence["require_symbols"] is False
    assert finding.evidence["expected"] is True

    service.get_account_password_policy.assert_called_once_with()
