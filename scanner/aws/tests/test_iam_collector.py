from datetime import datetime, timezone
from unittest.mock import Mock

from scanner.aws.collectors.iam import IAMDataCollector


def test_collect_iam_access_keys_normalizes_access_keys():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "user-one"},
        {"UserName": "user-two"},
    ]

    service.list_access_keys.side_effect = [
        [
            {
                "AccessKeyId": "AKIAUSERONE",
                "Status": "Active",
                "CreateDate": datetime(
                    2026,
                    1,
                    1,
                    tzinfo=timezone.utc,
                ),
            }
        ],
        [
            {
                "AccessKeyId": "AKIAUSERTWO",
                "Status": "Inactive",
                "CreateDate": datetime(
                    2025,
                    12,
                    1,
                    tzinfo=timezone.utc,
                ),
            }
        ],
    ]

    collector = IAMDataCollector(service)

    result = collector.collect_iam_access_keys()

    assert len(result) == 2

    assert result[0]["username"] == "user-one"
    assert result[0]["access_key_id"] == "AKIAUSERONE"
    assert result[0]["status"] == "Active"
    assert result[0]["created_at"] == datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    assert result[1]["username"] == "user-two"
    assert result[1]["access_key_id"] == "AKIAUSERTWO"
    assert result[1]["status"] == "Inactive"
    assert result[1]["created_at"] == datetime(
        2025,
        12,
        1,
        tzinfo=timezone.utc,
    )

    assert result[0]["current_time"] == result[1]["current_time"]
    assert result[0]["current_time"].tzinfo == timezone.utc

    assert service.list_users.call_count == 1
    assert service.list_access_keys.call_count == 2


def test_collect_password_policy_returns_normalized_password_policy():
    service = Mock()

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "AllowUsersToChangePassword": True,
        "ExpirePasswords": True,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 24,
    }

    collector = IAMDataCollector(service)

    result = collector.collect_password_policy()

    assert result == {
        "minimum_password_length": 14,
        "require_symbols": True,
        "require_numbers": True,
        "require_uppercase": True,
        "require_lowercase": True,
        "password_reuse_prevention": 24,
    }

    service.get_account_password_policy.assert_called_once_with()


def test_collect_password_policy_uses_cache():
    service = Mock()

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
        "RequireNumbers": True,
        "RequireUppercaseCharacters": True,
        "RequireLowercaseCharacters": True,
        "PasswordReusePrevention": 24,
    }

    collector = IAMDataCollector(service)

    first_result = collector.collect_password_policy()
    second_result = collector.collect_password_policy()

    assert first_result == second_result

    assert service.get_account_password_policy.call_count == 1


def test_collect_credential_report_returns_normalized_users():
    service = Mock()

    service.get_credential_report.return_value = {
        "Content": (
            b"user,password_enabled,password_last_used\n"
            b"alice,true,2026-01-01T00:00:00+00:00\n"
            b"bob,false,N/A\n"
        ),
        "ReportFormat": "text/csv",
    }

    collector = IAMDataCollector(service)

    result = collector.collect_credential_report()

    assert len(result) == 2

    assert result[0]["username"] == "alice"
    assert result[0]["password_enabled"] is True
    assert result[0]["password_last_used"] == datetime(
        2026,
        1,
        1,
        tzinfo=timezone.utc,
    )

    assert result[1]["username"] == "bob"
    assert result[1]["password_enabled"] is False
    assert result[1]["password_last_used"] is None

    assert result[0]["current_time"].tzinfo == timezone.utc
    assert result[1]["current_time"].tzinfo == timezone.utc
    assert result[0]["current_time"] == result[1]["current_time"]

    service.get_credential_report.assert_called_once_with()


def test_collect_credential_report_uses_cache():
    service = Mock()

    service.get_credential_report.return_value = {
        "Content": (
            b"user,password_enabled,password_last_used\n"
            b"alice,true,2026-01-01T00:00:00+00:00\n"
        ),
        "ReportFormat": "text/csv",
    }

    collector = IAMDataCollector(service)

    first_result = collector.collect_credential_report()
    second_result = collector.collect_credential_report()

    assert first_result == second_result

    assert service.get_credential_report.call_count == 1


def test_collect_broad_user_policies_normalizes_single_statement():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "AdminLikePolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "AdminLikePolicy"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "AdminLikePolicy",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "AdminLikePolicy"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
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

    collector = IAMDataCollector(service)

    result = collector.collect_broad_user_policies()

    assert result == [
        {
            "username": "alice",
            "policy_name": "AdminLikePolicy",
            "policy_arn": (
                "arn:aws:iam::123456789012:policy/"
                "AdminLikePolicy"
            ),
            "policy_version_id": "v1",
            "effect": "Allow",
            "action": "*",
            "resource": "*",
            "condition": None,
        }
    ]

    service.list_users.assert_called_once()
    service.list_attached_user_policies.assert_called_once_with(
        "alice"
    )
    service.get_policy.assert_called_once_with(
        "arn:aws:iam::123456789012:policy/"
        "AdminLikePolicy"
    )
    service.get_policy_version.assert_called_once_with(
        "arn:aws:iam::123456789012:policy/"
        "AdminLikePolicy",
        "v1",
    )


def test_collect_broad_user_policies_normalizes_multiple_statements():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "MixedPolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "MixedPolicy"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "MixedPolicy",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "MixedPolicy"
        ),
        "DefaultVersionId": "v3",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v3",
        },
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
                {
                    "Effect": "Deny",
                    "Action": "s3:DeleteBucket",
                    "Resource": "*",
                },
            ],
        },
    }

    collector = IAMDataCollector(service)

    result = collector.collect_broad_user_policies()

    assert len(result) == 2

    assert result[0]["effect"] == "Allow"
    assert result[0]["action"] == "*"
    assert result[0]["resource"] == "*"

    assert result[1]["effect"] == "Deny"
    assert result[1]["action"] == "s3:DeleteBucket"
    assert result[1]["resource"] == "*"


def test_collect_broad_user_policies_skips_policy_without_default_version():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "IncompletePolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "IncompletePolicy"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "IncompletePolicy",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "IncompletePolicy"
        ),
    }

    collector = IAMDataCollector(service)

    result = collector.collect_broad_user_policies()

    assert result == []

    service.get_policy_version.assert_not_called()


def test_collect_broad_user_policies_skips_policy_without_arn():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "MissingArnPolicy",
        }
    ]

    collector = IAMDataCollector(service)

    result = collector.collect_broad_user_policies()

    assert result == []

    service.get_policy.assert_not_called()
    service.get_policy_version.assert_not_called()


def test_collect_broad_user_policies_uses_cache():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]

    service.list_attached_user_policies.return_value = [
        {
            "PolicyName": "AdminLikePolicy",
            "PolicyArn": (
                "arn:aws:iam::123456789012:policy/"
                "AdminLikePolicy"
            ),
        }
    ]

    service.get_policy.return_value = {
        "PolicyName": "AdminLikePolicy",
        "Arn": (
            "arn:aws:iam::123456789012:policy/"
            "AdminLikePolicy"
        ),
        "DefaultVersionId": "v1",
    }

    service.get_policy_version.return_value = {
        "policy_version": {
            "VersionId": "v1",
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

    collector = IAMDataCollector(service)

    first_result = collector.collect_broad_user_policies()
    second_result = collector.collect_broad_user_policies()

    assert first_result == second_result

    assert service.list_users.call_count == 1
    assert service.list_attached_user_policies.call_count == 1
    assert service.get_policy.call_count == 1
    assert service.get_policy_version.call_count == 1


def test_collect_broad_user_inline_policies_normalizes_multiple_users_policies_and_statements():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
        {"UserName": "bob"},
    ]

    service.list_user_policies.side_effect = [
        [
            "AdminInline",
            "AuditInline",
        ],
        [
            "DeveloperInline",
        ],
    ]

    service.get_user_policy.side_effect = [
        {
            "policy_name": "AdminInline",
            "document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*",
                    },
                    {
                        "Effect": "Deny",
                        "Action": "s3:DeleteBucket",
                        "Resource": "*",
                    },
                ],
            },
        },
        {
            "policy_name": "AuditInline",
            "document": {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Action": "logs:*",
                    "Resource": "*",
                },
            },
        },
        {
            "policy_name": "DeveloperInline",
            "document": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ec2:Describe*",
                        "Resource": "*",
                    }
                ],
            },
        },
    ]

    collector = IAMDataCollector(service)

    result = collector.collect_broad_user_inline_policies()

    assert len(result) == 4

    assert result[0] == {
        "username": "alice",
        "policy_name": "AdminInline",
        "statement_index": 0,
        "effect": "Allow",
        "action": "*",
        "resource": "*",
        "condition": None,
    }

    assert result[1] == {
        "username": "alice",
        "policy_name": "AdminInline",
        "statement_index": 1,
        "effect": "Deny",
        "action": "s3:DeleteBucket",
        "resource": "*",
        "condition": None,
    }

    assert result[2] == {
        "username": "alice",
        "policy_name": "AuditInline",
        "statement_index": 0,
        "effect": "Allow",
        "action": "logs:*",
        "resource": "*",
        "condition": None,
    }

    assert result[3] == {
        "username": "bob",
        "policy_name": "DeveloperInline",
        "statement_index": 0,
        "effect": "Allow",
        "action": "ec2:Describe*",
        "resource": "*",
        "condition": None,
    }

    assert service.list_users.call_count == 1
    assert service.list_user_policies.call_count == 2

    service.list_user_policies.assert_any_call("alice")
    service.list_user_policies.assert_any_call("bob")

    assert service.get_user_policy.call_count == 3

    service.get_user_policy.assert_any_call(
        "alice",
        "AdminInline",
    )
    service.get_user_policy.assert_any_call(
        "alice",
        "AuditInline",
    )
    service.get_user_policy.assert_any_call(
        "bob",
        "DeveloperInline",
    )


def test_collect_broad_user_inline_policies_skips_invalid_statements():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]

    service.list_user_policies.return_value = [
        "MixedInline",
    ]

    service.get_user_policy.return_value = {
        "policy_name": "MixedInline",
        "document": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*",
                },
                "invalid-statement",
                None,
                {
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Resource": "*",
                },
            ],
        },
    }

    collector = IAMDataCollector(service)

    result = collector.collect_broad_user_inline_policies()

    assert result == [
        {
            "username": "alice",
            "policy_name": "MixedInline",
            "statement_index": 0,
            "effect": "Allow",
            "action": "*",
            "resource": "*",
            "condition": None,
        },
        {
            "username": "alice",
            "policy_name": "MixedInline",
            "statement_index": 3,
            "effect": "Deny",
            "action": "s3:*",
            "resource": "*",
            "condition": None,
        },
    ]


def test_collect_broad_user_inline_policies_uses_cache():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
    ]

    service.list_user_policies.return_value = [
        "AdminInline",
    ]

    service.get_user_policy.return_value = {
        "policy_name": "AdminInline",
        "document": {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            },
        },
    }

    collector = IAMDataCollector(service)

    first_result = collector.collect_broad_user_inline_policies()
    second_result = collector.collect_broad_user_inline_policies()

    assert first_result == second_result

    assert service.list_users.call_count == 1
    assert service.list_user_policies.call_count == 1
    assert service.get_user_policy.call_count == 1

    service.list_user_policies.assert_called_once_with(
        "alice"
    )

    service.get_user_policy.assert_called_once_with(
        "alice",
        "AdminInline",
    )
