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
    }

    service.get_account_password_policy.assert_called_once_with()

def test_collect_password_policy_uses_cache():
    service = Mock()

    service.get_account_password_policy.return_value = {
        "MinimumPasswordLength": 14,
        "RequireSymbols": True,
    }

    collector = IAMDataCollector(service)

    first_result = collector.collect_password_policy()
    second_result = collector.collect_password_policy()

    assert first_result == second_result

    assert service.get_account_password_policy.call_count == 1
