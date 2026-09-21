from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.aws.scanners.iam import IAMScanner


def _configure_credential_report(service):
    service.get_credential_report.return_value = {
        "Content": b"user,password_enabled,password_last_used\n",
        "ReportFormat": "text/csv",
    }


def _configure_broad_user_inline_policies(service):
    service.list_user_policies.return_value = []


def _configure_broad_group_policies(service):
    service.list_groups_for_user.return_value = []
    service.list_attached_group_policies.return_value = []
    service.list_groups.return_value = []
    service.list_group_policies.return_value = []
    service.get_group_policy.return_value = {}


def test_iam_scanner_evaluates_access_key_rules_together():
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
            "AccessKeyId": "AKIAOLD123",
            "Status": "Active",
            "CreateDate": datetime(
                2025,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        },
        {
            "AccessKeyId": "AKIAINACTIVE123",
            "Status": "Inactive",
            "CreateDate": datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    _configure_credential_report(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    rule_ids = [finding.rule_id for finding in findings]

    assert "CS-AWS-IAM-003" in rule_ids
    assert "CS-AWS-IAM-004" in rule_ids

    iam003_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-003"
    ]

    iam004_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-004"
    ]

    assert len(iam003_findings) == 1
    assert len(iam004_findings) == 1

    assert iam003_findings[0].resource_type == "aws_iam_user"
    assert iam003_findings[0].resource_id == "test-user"
    assert iam003_findings[0].evidence["access_key_id"] == "AKIAOLD123"
    assert iam004_findings[0].resource_id == "AKIAINACTIVE123"

    service.list_users.assert_called_once()
    service.list_access_keys.assert_called_once_with(
        "test-user"
    )


def test_iam_scanner_detects_multiple_active_access_keys():
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
            "AccessKeyId": "AKIAACTIVE001",
            "Status": "Active",
            "CreateDate": datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        },
        {
            "AccessKeyId": "AKIAACTIVE002",
            "Status": "Active",
            "CreateDate": datetime(
                2026,
                2,
                1,
                tzinfo=timezone.utc,
            ),
        },
        {
            "AccessKeyId": "AKIAINACTIVE001",
            "Status": "Inactive",
            "CreateDate": datetime(
                2026,
                3,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    _configure_credential_report(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam017_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-017"
    ]

    assert len(iam017_findings) == 1

    finding = iam017_findings[0]

    assert finding.resource_id == "test-user"
    assert finding.resource_type == "iam_user"
    assert finding.severity.value == "medium"

    assert finding.evidence == {
        "username": "test-user",
        "active_access_key_count": 2,
        "active_access_key_ids": [
            "AKIAACTIVE001",
            "AKIAACTIVE002",
        ],
    }


def test_iam_scanner_does_not_detect_single_active_access_key():
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
            "AccessKeyId": "AKIAACTIVE001",
            "Status": "Active",
            "CreateDate": datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        },
        {
            "AccessKeyId": "AKIAINACTIVE001",
            "Status": "Inactive",
            "CreateDate": datetime(
                2026,
                2,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    _configure_credential_report(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam017_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-017"
    ]

    assert iam017_findings == []


def test_iam_scanner_detects_multiple_authentication_methods():
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
            "AccessKeyId": "AKIAACTIVE001",
            "Status": "Active",
            "CreateDate": datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    service.get_credential_report.return_value = {
        "Content": (
            b"user,password_enabled,password_last_used\n"
            b"test-user,true,2026-09-01T00:00:00+00:00\n"
        ),
        "ReportFormat": "text/csv",
    }

    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam018_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-018"
    ]

    assert len(iam018_findings) == 1

    finding = iam018_findings[0]

    assert finding.resource_id == "test-user"
    assert finding.resource_type == "iam_user"
    assert finding.severity.value == "medium"

    assert finding.evidence == {
        "username": "test-user",
        "password_enabled": True,
        "active_access_key_count": 1,
        "active_access_key_ids": [
            "AKIAACTIVE001",
        ],
    }


def test_iam_scanner_does_not_detect_multiple_authentication_methods_when_password_disabled():
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
            "AccessKeyId": "AKIAACTIVE001",
            "Status": "Active",
            "CreateDate": datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    service.get_credential_report.return_value = {
        "Content": (
            b"user,password_enabled,password_last_used\n"
            b"test-user,false,N/A\n"
        ),
        "ReportFormat": "text/csv",
    }

    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam018_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-018"
    ]

    assert iam018_findings == []


def test_iam_scanner_does_not_detect_multiple_authentication_methods_without_active_key():
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
            "AccessKeyId": "AKIAINACTIVE001",
            "Status": "Inactive",
            "CreateDate": datetime(
                2026,
                1,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    service.get_credential_report.return_value = {
        "Content": (
            b"user,password_enabled,password_last_used\n"
            b"test-user,true,2026-09-01T00:00:00+00:00\n"
        ),
        "ReportFormat": "text/csv",
    }

    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam018_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-018"
    ]

    assert iam018_findings == []


def test_iam_scanner_detects_active_access_key_that_has_never_been_used():
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
            "AccessKeyId": "AKIANEVERUSED123",
            "Status": "Active",
            "CreateDate": datetime(
                2026,
                9,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_access_key_last_used.return_value = None

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    _configure_credential_report(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam019_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-019"
    ]

    assert len(iam019_findings) == 1

    finding = iam019_findings[0]

    assert finding.resource_id == "AKIANEVERUSED123"
    assert finding.resource_type == "iam_access_key"
    assert finding.severity.value == "medium"

    assert finding.evidence == {
        "username": "test-user",
        "access_key_id": "AKIANEVERUSED123",
        "status": "Active",
        "last_used_at": None,
        "never_used": True,
    }

    service.get_access_key_last_used.assert_called_once_with(
        "AKIANEVERUSED123"
    )


def test_iam_scanner_does_not_detect_active_access_key_that_was_used():
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
            "AccessKeyId": "AKIAUSED123",
            "Status": "Active",
            "CreateDate": datetime(
                2026,
                9,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_access_key_last_used.return_value = datetime(
        2026,
        9,
        15,
        10,
        30,
        tzinfo=timezone.utc,
    )

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    _configure_credential_report(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam019_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-019"
    ]

    assert iam019_findings == []

    service.get_access_key_last_used.assert_called_once_with(
        "AKIAUSED123"
    )


def test_iam_scanner_does_not_detect_inactive_access_key_that_has_never_been_used():
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
                9,
                1,
                tzinfo=timezone.utc,
            ),
        },
    ]

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
    }

    service.list_attached_user_policies.return_value = []

    _configure_credential_report(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam019_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-019"
    ]

    assert iam019_findings == []

    service.get_access_key_last_used.assert_not_called()
