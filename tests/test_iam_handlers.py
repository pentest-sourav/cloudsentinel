from unittest.mock import MagicMock

from engine.rules.registry.iam_handlers import (
    IAM_DATA_SOURCE_HANDLERS,
    collect_no_active_authentication_credentials,
)


def test_iam_data_source_handlers_have_expected_sources():
    expected_sources = {
        "root_mfa",
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
