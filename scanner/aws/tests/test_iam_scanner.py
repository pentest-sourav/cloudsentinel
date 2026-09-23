from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.aws.scanners.iam import IAMScanner


def _configure_credential_report(service):
    service.get_credential_report.return_value = {
        "Content": b"user,password_enabled,password_last_used\n",
        "ReportFormat": "text/csv",
    }


def _configure_broad_user_policies(service):
    service.list_attached_user_policies.return_value = []

    service.get_policy.return_value = {}

    service.get_policy_version.return_value = {
        "policy_version": {},
        "document": {},
    }


def _configure_broad_user_inline_policies(service):
    service.list_user_policies.return_value = []


def _configure_broad_group_policies(service):
    service.list_groups_for_user.return_value = []
    service.list_attached_group_policies.return_value = []
    service.list_groups.return_value = []
    service.list_group_policies.return_value = []
    service.get_group_policy.return_value = {}


def _configure_common_iam_service(service, username):
    service.get_root_mfa_status.return_value = True
    service.get_root_access_keys_present.return_value = False

    service.list_users.return_value = [
        {"UserName": username},
    ]

    service.list_mfa_devices.return_value = [
        {
            "SerialNumber": (
                f"arn:aws:iam::123456789012:mfa/{username}"
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
    _configure_broad_user_policies(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    # IAM-036: Access Analyzer returns no security warnings
    # unless a test explicitly configures them.
    service.validate_policy.return_value = []


def test_iam_scanner_detects_old_active_access_key():
    service = Mock()
    service.list_roles.return_value = []

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
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

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
    assert finding.evidence["username"] == "test-user"


def test_iam_scanner_returns_root_and_user_mfa_findings():
    service = Mock()
    service.list_roles.return_value = []

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
    _configure_broad_user_policies(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    scanner = IAMScanner(service)

    findings = scanner.scan()

    rule_ids = [finding.rule_id for finding in findings]

    assert "CS-AWS-IAM-001" in rule_ids
    assert "CS-AWS-IAM-002" in rule_ids


def test_iam_scanner_returns_no_mfa_findings_when_users_are_protected():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "protected-user",
    )

    scanner = IAMScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_iam_scanner_uses_registry_data_sources():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "test-user",
    )

    scanner = IAMScanner(service)

    findings = scanner.scan()

    service.get_root_mfa_status.assert_called_once()
    service.list_users.assert_called_once()
    service.list_access_keys.assert_called_once()
    service.get_credential_report.assert_called_once()

    service.list_attached_user_policies.assert_any_call(
        "test-user"
    )
    assert (
        service.list_attached_user_policies.call_count
        == 3
    )

    service.list_user_policies.assert_any_call(
        "test-user"
    )
    assert (
        service.list_user_policies.call_count
        == 3
    )

    service.list_groups_for_user.assert_called_once_with(
        "test-user"
    )

    service.list_groups.assert_called_once_with()

    service.list_group_policies.assert_not_called()
    service.get_group_policy.assert_not_called()

    assert findings == []


def test_iam_scanner_returns_broad_group_policy_finding():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups_for_user.return_value = [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE",
        }
    ]

    service.list_attached_group_policies.return_value = [
        {
            "PolicyName": "DeveloperAccess",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "DeveloperAccess"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "DeveloperAccess",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "DeveloperAccess"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
            "IsDefaultVersion": True,
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_013_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-013"
    ]

    assert len(iam_013_findings) == 1

    finding = iam_013_findings[0]

    assert finding.title == (
        "IAM User Receives Broad Permissions Through Group"
    )

    assert finding.resource_id == "alice"

    assert finding.evidence["username"] == "alice"
    assert finding.evidence["group_name"] == "Developers"
    assert finding.evidence["policy_name"] == "DeveloperAccess"
    assert finding.evidence["policy_version_id"] == "v1"
    assert finding.evidence["action"] == "*"
    assert finding.evidence["resource"] == "*"
    assert finding.evidence["permission_source"] == "iam_group"

    service.list_groups_for_user.assert_called_once_with(
        "alice"
    )

    service.list_attached_group_policies.assert_called_once_with(
        "Developers"
    )

    service.get_policy.assert_called_once_with(
        "arn:aws:iam::123456789012:policy/"
        "DeveloperAccess"
    )

    service.get_policy_version.assert_called_once_with(
        "arn:aws:iam::123456789012:policy/"
        "DeveloperAccess",
        "v1",
    )


def test_iam_scanner_does_not_report_specific_group_permissions():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups_for_user.return_value = [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE",
        }
    ]

    service.list_attached_group_policies.return_value = [
        {
            "PolicyName": "DeveloperAccess",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "DeveloperAccess"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "DeveloperAccess",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "DeveloperAccess"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
            "IsDefaultVersion": True,
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": (
                    "arn:aws:s3:::example-bucket/*"
                ),
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_013_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-013"
    ]

    assert iam_013_findings == []


def test_iam_scanner_does_not_report_group_deny_statement():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups_for_user.return_value = [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE",
        }
    ]

    service.list_attached_group_policies.return_value = [
        {
            "PolicyName": "DeveloperAccess",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "DeveloperAccess"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "DeveloperAccess",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "DeveloperAccess"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
            "IsDefaultVersion": True,
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_013_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-013"
    ]

    assert iam_013_findings == []


def test_iam_scanner_reuses_group_policy_collection_for_shared_group():
    service = Mock()
    service.list_roles.return_value = []

    service.get_root_mfa_status.return_value = True
    service.get_root_access_keys_present.return_value = False

    service.list_users.return_value = [
        {"UserName": "alice"},
        {"UserName": "bob"},
    ]

    service.list_mfa_devices.return_value = [
        {
            "SerialNumber": (
                "arn:aws:iam::123456789012:mfa/alice"
            )
        },
        {
            "SerialNumber": (
                "arn:aws:iam::123456789012:mfa/bob"
            )
        },
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
    _configure_broad_user_policies(service)
    _configure_broad_user_inline_policies(service)
    _configure_broad_group_policies(service)

    service.list_groups_for_user.side_effect = [
        [
            {
                "GroupName": "Developers",
                "GroupId": "AGPAEXAMPLE",
            }
        ],
        [
            {
                "GroupName": "Developers",
                "GroupId": "AGPAEXAMPLE",
            }
        ],
    ]

    service.list_attached_group_policies.return_value = []

    scanner = IAMScanner(service)

    findings = scanner.scan()

    assert findings == []

    assert service.list_groups_for_user.call_count == 2

    service.list_attached_group_policies.assert_called_once_with(
        "Developers"
    )

    service.list_groups.assert_called_once_with()


def test_iam_scanner_returns_broad_user_inline_policy_finding():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_user_policies.return_value = [
        "AdminInlinePolicy",
    ]

    service.get_user_policy.return_value = {
        "policy_name": "AdminInlinePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_014_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-014"
    ]

    assert len(iam_014_findings) == 1

    finding = iam_014_findings[0]

    assert finding.title == (
        "IAM User Inline Policy Grants Broad Permissions"
    )

    assert finding.resource_id == "alice"
    assert finding.severity.value == "high"

    assert finding.evidence["username"] == "alice"
    assert finding.evidence["policy_name"] == "AdminInlinePolicy"
    assert finding.evidence["effect"] == "Allow"
    assert finding.evidence["action"] == "*"
    assert finding.evidence["resource"] == "*"
    assert finding.evidence["broad_permission"] is True
    assert (
        finding.evidence["permission_source"]
        == "iam_user_inline"
    )

    service.list_user_policies.assert_any_call(
        "alice"
    )
    assert service.list_user_policies.call_count == 3

    service.get_user_policy.assert_any_call(
        "alice",
        "AdminInlinePolicy",
    )
    assert service.get_user_policy.call_count == 2


def test_iam_scanner_returns_broad_group_inline_policy_finding():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups.return_value = [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE",
        }
    ]

    service.list_group_policies.return_value = [
        "AdminInlinePolicy",
    ]

    service.get_group_policy.return_value = {
        "policy_name": "AdminInlinePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_015_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-015"
    ]

    assert len(iam_015_findings) == 1

    finding = iam_015_findings[0]

    assert finding.title == (
        "IAM Group Inline Policy Grants Broad Permissions"
    )

    assert finding.resource_type == "iam_group"
    assert finding.resource_id == "Developers"
    assert finding.severity.value == "high"

    assert finding.evidence["group_name"] == "Developers"
    assert (
        finding.evidence["policy_name"]
        == "AdminInlinePolicy"
    )
    assert finding.evidence["statement_index"] == 0
    assert finding.evidence["effect"] == "Allow"
    assert finding.evidence["action"] == "*"
    assert finding.evidence["resource"] == "*"
    assert finding.evidence["broad_permission"] is True
    assert (
        finding.evidence["permission_source"]
        == "iam_group_inline"
    )

    service.list_groups.assert_called_once_with()

    service.list_group_policies.assert_any_call(
        "Developers"
    )
    assert service.list_group_policies.call_count == 1

    service.get_group_policy.assert_any_call(
        "Developers",
        "AdminInlinePolicy",
    )
    assert service.get_group_policy.call_count == 2


def test_iam_scanner_does_not_report_broad_group_inline_policy_for_specific_action():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups.return_value = [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE",
        }
    ]

    service.list_group_policies.return_value = [
        "DeveloperInlinePolicy",
    ]

    service.get_group_policy.return_value = {
        "policy_name": "DeveloperInlinePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_015_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-015"
    ]

    assert iam_015_findings == []

    service.list_groups.assert_called_once_with()

    service.list_group_policies.assert_any_call(
        "Developers"
    )
    assert service.list_group_policies.call_count == 1

    service.get_group_policy.assert_any_call(
        "Developers",
        "DeveloperInlinePolicy",
    )
    assert service.get_group_policy.call_count == 2


def test_iam_scanner_does_not_report_broad_group_inline_policy_for_deny_statement():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups.return_value = [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE",
        }
    ]

    service.list_group_policies.return_value = [
        "DenyInlinePolicy",
    ]

    service.get_group_policy.return_value = {
        "policy_name": "DenyInlinePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_015_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-015"
    ]

    assert iam_015_findings == []

    service.list_groups.assert_called_once_with()

    service.list_group_policies.assert_any_call(
        "Developers"
    )
    assert service.list_group_policies.call_count == 1

    service.get_group_policy.assert_any_call(
        "Developers",
        "DenyInlinePolicy",
    )
    assert service.get_group_policy.call_count == 2


def test_iam_scanner_detects_broad_inline_policy_on_orphan_group():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups.return_value = [
        {
            "GroupName": "LegacyAdmins",
            "GroupId": "AGPAORPHAN",
        }
    ]

    service.list_group_policies.return_value = [
        "LegacyAdminInlinePolicy",
    ]

    service.get_group_policy.return_value = {
        "policy_name": "LegacyAdminInlinePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_015_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-015"
    ]

    assert len(iam_015_findings) == 1

    finding = iam_015_findings[0]

    assert finding.resource_type == "iam_group"
    assert finding.resource_id == "LegacyAdmins"
    assert finding.severity.value == "high"

    assert finding.evidence["group_name"] == "LegacyAdmins"
    assert (
        finding.evidence["policy_name"]
        == "LegacyAdminInlinePolicy"
    )
    assert finding.evidence["statement_index"] == 0
    assert finding.evidence["effect"] == "Allow"
    assert finding.evidence["action"] == "*"
    assert finding.evidence["resource"] == "*"
    assert finding.evidence["broad_permission"] is True
    assert (
        finding.evidence["permission_source"]
        == "iam_group_inline"
    )

    service.list_groups.assert_called_once_with()

    service.list_group_policies.assert_any_call(
        "LegacyAdmins"
    )
    assert service.list_group_policies.call_count == 1

    service.get_group_policy.assert_any_call(
        "LegacyAdmins",
        "LegacyAdminInlinePolicy",
    )
    assert service.get_group_policy.call_count == 2

    service.list_groups_for_user.assert_called_once_with(
        "alice"
    )

def test_iam_scanner_detects_broad_action_on_scoped_user_managed_policy():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "ScopedAdmin",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "ScopedAdmin"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "ScopedAdmin",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "ScopedAdmin"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
            "IsDefaultVersion": True,
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "arn:aws:s3:::sensitive-bucket/*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_016_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-016"
    ]

    assert len(iam_016_findings) == 1

    finding = iam_016_findings[0]

    assert finding.title == (
        "IAM Policy Grants Broad Actions on Scoped Resources"
    )
    assert finding.resource_id == "alice"
    assert finding.severity.value == "medium"
    assert finding.evidence["permission_source"] == (
        "user_managed_policy"
    )
    assert finding.evidence["principal_type"] == "user"
    assert finding.evidence["principal_id"] == "alice"
    assert finding.evidence["policy_name"] == "ScopedAdmin"
    assert finding.evidence["policy_version_id"] == "v1"
    assert finding.evidence["effect"] == "Allow"
    assert finding.evidence["action"] == "*"
    assert finding.evidence["resource"] == (
        "arn:aws:s3:::sensitive-bucket/*"
    )
    assert finding.evidence["broad_action"] is True
    assert finding.evidence["scoped_resource"] is True

    service.list_attached_user_policies.assert_any_call(
        "alice"
    )
    assert service.list_attached_user_policies.call_count == 3
    service.get_policy.assert_any_call(
        "arn:aws:iam::123456789012:policy/"
        "ScopedAdmin"
    )
    assert service.get_policy.call_count == 2
    service.get_policy_version.assert_any_call(
        "arn:aws:iam::123456789012:policy/"
        "ScopedAdmin",
        "v1",
    )
    assert service.get_policy_version.call_count == 2


def test_iam_scanner_detects_broad_action_on_scoped_group_managed_policy():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups_for_user.return_value = [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE",
        }
    ]

    service.list_attached_group_policies.return_value = [
        {
            "PolicyName": "ScopedGroupAdmin",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "ScopedGroupAdmin"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "ScopedGroupAdmin",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "ScopedGroupAdmin"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
            "IsDefaultVersion": True,
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": ["*"],
                "Resource": [
                    "arn:aws:s3:::sensitive-bucket/*",
                ],
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_016_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-016"
    ]

    assert len(iam_016_findings) == 1

    finding = iam_016_findings[0]

    assert finding.resource_id == "Developers"
    assert finding.evidence["permission_source"] == (
        "group_managed_policy"
    )
    assert finding.evidence["principal_type"] == "group"
    assert finding.evidence["principal_id"] == "Developers"
    assert finding.evidence["username"] == "alice"
    assert finding.evidence["group_name"] == "Developers"
    assert finding.evidence["action"] == ["*"]
    assert finding.evidence["resource"] == [
        "arn:aws:s3:::sensitive-bucket/*",
    ]


def test_iam_scanner_detects_broad_action_on_scoped_user_inline_policy():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_user_policies.return_value = [
        "ScopedInlinePolicy",
    ]

    service.get_user_policy.return_value = {
        "policy_name": "ScopedInlinePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": (
                    "arn:aws:dynamodb:eu-north-1:"
                    "123456789012:table/Users"
                ),
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_016_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-016"
    ]

    assert len(iam_016_findings) == 1

    finding = iam_016_findings[0]

    assert finding.resource_id == "alice"
    assert finding.evidence["permission_source"] == (
        "user_inline_policy"
    )
    assert finding.evidence["principal_type"] == "user"
    assert finding.evidence["principal_id"] == "alice"
    assert finding.evidence["policy_name"] == "ScopedInlinePolicy"
    assert finding.evidence["statement_index"] == 0
    assert finding.evidence["action"] == "*"
    assert finding.evidence["resource"] == (
        "arn:aws:dynamodb:eu-north-1:"
        "123456789012:table/Users"
    )


def test_iam_scanner_detects_broad_action_on_scoped_group_inline_policy():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_groups.return_value = [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE",
        }
    ]

    service.list_group_policies.return_value = [
        "ScopedGroupInlinePolicy",
    ]

    service.get_group_policy.return_value = {
        "policy_name": "ScopedGroupInlinePolicy",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": (
                    "arn:aws:s3:::sensitive-bucket/*"
                ),
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_016_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-016"
    ]

    assert len(iam_016_findings) == 1

    finding = iam_016_findings[0]

    assert finding.resource_type == "iam_identity"
    assert finding.resource_id == "Developers"
    assert finding.severity.value == "medium"
    assert finding.evidence["permission_source"] == (
        "group_inline_policy"
    )
    assert finding.evidence["principal_type"] == "group"
    assert finding.evidence["principal_id"] == "Developers"
    assert finding.evidence["group_name"] == "Developers"
    assert finding.evidence["policy_name"] == (
        "ScopedGroupInlinePolicy"
    )
    assert finding.evidence["statement_index"] == 0
    assert finding.evidence["broad_action"] is True
    assert finding.evidence["scoped_resource"] is True


def test_iam_scanner_does_not_duplicate_iam_012_to_015_for_full_wildcards():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "FullAdmin",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "FullAdmin"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "FullAdmin",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "FullAdmin"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
            "IsDefaultVersion": True,
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_016_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-016"
    ]

    iam_012_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-012"
    ]

    assert iam_016_findings == []
    assert len(iam_012_findings) == 1


def test_iam_scanner_does_not_report_broad_action_for_deny_statement():
    service = Mock()
    service.list_roles.return_value = []

    _configure_common_iam_service(
        service,
        "alice",
    )

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "DeniedScopedAccess",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "DeniedScopedAccess"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "DeniedScopedAccess",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "DeniedScopedAccess"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
            "IsDefaultVersion": True,
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "arn:aws:s3:::sensitive-bucket/*",
            },
        },
    }

    scanner = IAMScanner(service)

    findings = scanner.scan()

    iam_016_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-IAM-016"
    ]

    assert iam_016_findings == []
