from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.aws.scanners.iam import IAMScanner


def _configure_credential_report(service):
    service.get_credential_report.return_value = {
        "Content": b"user,password_enabled,password_last_used\n",
        "ReportFormat": "text/csv",
    }


def test_iam_scanner_detects_old_active_access_key():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireLowercaseCharacters": True,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 24,
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

    service.list_attached_user_policies.return_value = []

    _configure_credential_report(service)

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
        "RequireLowercaseCharacters": True,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 24,
    }

    _configure_credential_report(service)

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
        "RequireLowercaseCharacters": True,
        "RequireSymbols": False,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 24,
    }

    _configure_credential_report(service)

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


def test_iam_scanner_detects_password_policy_without_numbers():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.list_users.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireLowercaseCharacters": True,
        "RequireSymbols": True,
        "RequireNumbers": False,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 24,
    }

    _configure_credential_report(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam007_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-007"
    ]

    assert len(iam007_findings) == 1

    finding = iam007_findings[0]

    assert finding.resource_id == "account-password-policy"
    assert finding.severity.value == "medium"
    assert finding.evidence["require_numbers"] is False
    assert finding.evidence["expected"] is True

    service.get_account_password_policy.assert_called_once_with()


def test_iam_scanner_detects_multiple_password_policy_findings():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.list_users.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireLowercaseCharacters": False,
        "RequireSymbols": False,
        "RequireNumbers": False,
        "RequireUppercaseCharacters": False,
        "PasswordReusePrevention": 0,
    }

    _configure_credential_report(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    password_policy_findings = {
        finding.rule_id: finding
        for finding in findings
        if finding.resource_type == "iam_password_policy"
    }

    assert "CS-AWS-IAM-006" in password_policy_findings
    assert "CS-AWS-IAM-007" in password_policy_findings
    assert "CS-AWS-IAM-008" in password_policy_findings
    assert "CS-AWS-IAM-009" in password_policy_findings
    assert "CS-AWS-IAM-010" in password_policy_findings

    assert (
        password_policy_findings[
            "CS-AWS-IAM-006"
        ].evidence["require_symbols"]
        is False
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-007"
        ].evidence["require_numbers"]
        is False
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-008"
        ].evidence["require_uppercase"]
        is False
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-009"
        ].evidence["require_lowercase"]
        is False
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-010"
        ].evidence["password_reuse_prevention"]
        == 0
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-006"
        ].severity.value
        == "medium"
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-007"
        ].severity.value
        == "medium"
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-008"
        ].severity.value
        == "medium"
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-009"
        ].severity.value
        == "medium"
    )

    assert (
        password_policy_findings[
            "CS-AWS-IAM-010"
        ].severity.value
        == "medium"
    )

    service.get_account_password_policy.assert_called_once_with()


def test_iam_scanner_detects_password_policy_without_uppercase():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.list_users.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireLowercaseCharacters": True,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": False,
        "PasswordReusePrevention": 24,
    }

    _configure_credential_report(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam008_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-008"
    ]

    assert len(iam008_findings) == 1

    finding = iam008_findings[0]

    assert finding.resource_id == "account-password-policy"
    assert finding.severity.value == "medium"
    assert finding.evidence["require_uppercase"] is False
    assert finding.evidence["expected"] is True

    service.get_account_password_policy.assert_called_once_with()


def test_iam_scanner_detects_password_policy_without_reuse_prevention():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.list_users.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireLowercaseCharacters": True,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 0,
    }

    _configure_credential_report(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam010_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-010"
    ]

    assert len(iam010_findings) == 1

    finding = iam010_findings[0]

    assert finding.resource_id == "account-password-policy"
    assert finding.severity.value == "medium"
    assert finding.evidence["password_reuse_prevention"] == 0
    assert finding.evidence["expected"] == 1

    service.get_account_password_policy.assert_called_once_with()


def test_iam_scanner_detects_password_policy_without_lowercase():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.list_users.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireLowercaseCharacters": False,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 24,
    }

    _configure_credential_report(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam009_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-009"
    ]

    assert len(iam009_findings) == 1

    finding = iam009_findings[0]

    assert finding.resource_id == "account-password-policy"
    assert finding.severity.value == "medium"
    assert finding.evidence["require_lowercase"] is False
    assert finding.evidence["expected"] is True

    service.get_account_password_policy.assert_called_once_with()


def test_iam_scanner_detects_unused_console_password():
    service = Mock()

    service.get_account_summary.return_value = {
        "AccountMFAEnabled": 1,
    }

    service.list_users.return_value = []

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireLowercaseCharacters": True,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "PasswordReusePrevention": 24,
    }

    service.get_credential_report.return_value = {
        "Content": (
            b"user,password_enabled,password_last_used\n"
            b"old-user,true,2026-01-01T00:00:00+00:00\n"
        ),
        "ReportFormat": "text/csv",
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam011_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-011"
    ]

    assert len(iam011_findings) == 1

    finding = iam011_findings[0]

    assert finding.resource_id == "old-user"
    assert finding.severity.value == "medium"
    assert finding.resource_type == "iam_user"
    assert finding.evidence["username"] == "old-user"
    assert finding.evidence["password_enabled"] is True
    assert finding.evidence["threshold_days"] == 90

    service.get_credential_report.assert_called_once_with()
