from unittest.mock import MagicMock

from engine.rules.registry.iam_handlers import (
    IAM_DATA_SOURCE_HANDLERS,
    collect_no_active_authentication_credentials,
)


def test_iam_data_source_handlers_have_expected_sources():
    expected_sources = {
        "root_mfa",
        "root_access_key",
        "iam_users",
        "iam_access_keys",
        "password_policy",
        "credential_report",
        "broad_user_policies",
        "broad_group_policies",
        "broad_user_inline_policies",
        "broad_group_inline_policies",
        "broad_action_restricted_resources",
        "multiple_active_access_keys",
        "multiple_authentication_methods",
        "access_key_last_used",
        "no_active_authentication_credentials",
        "user_attached_policies",
        "stale_iam_users",
        "administrative_group_policies",
        "privileged_users_without_boundary",
            "privileged_roles_without_boundary",
        "wildcard_role_trust_principals",
        "self_modifiable_policies",
        "cross_account_role_trusts",
        "access_analyzer_policy_validation",
    }

    assert set(IAM_DATA_SOURCE_HANDLERS) == expected_sources


def test_iam_data_source_handlers_are_callable():
    for handler in IAM_DATA_SOURCE_HANDLERS.values():
        assert callable(handler)


def test_collect_no_active_authentication_credentials_delegates_to_collector():
    collector = MagicMock()

    expected = [
        {
            "username": "alice",
            "password_enabled": False,
            "active_access_key_count": 0,
            "active_access_key_ids": [],
        }
    ]

    collector.collect_no_active_authentication_credentials.return_value = (
        expected
    )

    result = collect_no_active_authentication_credentials(collector)

    assert result == expected

    collector.collect_no_active_authentication_credentials.assert_called_once_with()


def test_collect_root_access_key_delegates_to_collector():
    collector = MagicMock()

    expected = {
        "access_keys_present": True,
    }

    collector.collect_root_access_key.return_value = expected

    result = IAM_DATA_SOURCE_HANDLERS["root_access_key"](collector)

    assert result == expected

    collector.collect_root_access_key.assert_called_once_with()


def test_collect_user_attached_policies_delegates_to_collector():
    collector = MagicMock()

    expected = [
        {
            "username": "alice",
            "managed_policy_count": 1,
            "managed_policy_names": [
                "ReadOnlyAccess",
            ],
            "inline_policy_count": 0,
            "inline_policy_names": [],
        }
    ]

    collector.collect_user_attached_policies.return_value = expected

    result = IAM_DATA_SOURCE_HANDLERS[
        "user_attached_policies"
    ](collector)

    assert result == expected

    collector.collect_user_attached_policies.assert_called_once_with()


def test_collect_administrative_group_policies_delegates_to_collector():
    collector = MagicMock()

    expected = [
        {
            "group_name": "Administrators",
            "policy_name": "AdministratorAccess",
            "policy_arn": (
                "arn:aws:iam::aws:policy/"
                "AdministratorAccess"
            ),
        }
    ]

    collector.collect_administrative_group_policies.return_value = (
        expected
    )

    from engine.rules.registry.iam_handlers import (
        collect_administrative_group_policies,
    )

    result = collect_administrative_group_policies(collector)

    assert result == expected

    collector.collect_administrative_group_policies.assert_called_once_with()


def test_collect_cross_account_role_trusts_delegates_to_collector():
    collector = MagicMock()

    expected = [
        {
            "role_name": "ProductionRole",
            "role_arn": (
                "arn:aws:iam::111111111111:"
                "role/ProductionRole"
            ),
            "statement_index": 0,
            "effect": "Allow",
            "principal": {
                "AWS": "222222222222",
            },
            "action": "sts:AssumeRole",
            "condition": None,
        }
    ]

    collector.collect_cross_account_role_trusts.return_value = (
        expected
    )

    from engine.rules.registry.iam_handlers import (
        collect_cross_account_role_trusts,
    )

    result = collect_cross_account_role_trusts(collector)

    assert result == expected

    collector.collect_cross_account_role_trusts.assert_called_once_with()
