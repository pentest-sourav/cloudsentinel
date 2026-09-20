from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.aws.scanners.iam import IAMScanner


def _configure_credential_report(service):
    service.get_credential_report.return_value = {
        "Content": b"user,password_enabled,password_last_used\n",
        "ReportFormat": "text/csv",
    }


def test_iam_scanner_detects_inactive_access_key():
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

    service.list_access_keys.return_value = [
        {
            "AccessKeyId": "AKIAINACTIVE123",
            "Status": "Inactive",
            "CreateDate": datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        }
    ]

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    _configure_credential_report(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam004_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-004"
    ]

    assert len(iam004_findings) == 1

    finding = iam004_findings[0]

    assert finding.resource_id == "AKIAINACTIVE123"
    assert finding.severity.value == "medium"
    assert finding.evidence["username"] == "test-user"
    assert finding.evidence["status"] == "Inactive"
