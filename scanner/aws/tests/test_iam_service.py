from unittest.mock import Mock

from scanner.aws.services.iam import IAMService


def test_list_access_keys_returns_access_key_metadata():
    session = Mock()
    iam_client = Mock()

    iam_client.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "UserName": "cloudsentinel-auditor",
                "AccessKeyId": "AKIAEXAMPLE123",
                "Status": "Active",
                "CreateDate": "2026-01-01T00:00:00Z",
            }
        ]
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_access_keys(
        "cloudsentinel-auditor"
    )

    assert result == [
        {
            "UserName": "cloudsentinel-auditor",
            "AccessKeyId": "AKIAEXAMPLE123",
            "Status": "Active",
            "CreateDate": "2026-01-01T00:00:00Z",
        }
    ]

    iam_client.list_access_keys.assert_called_once_with(
        UserName="cloudsentinel-auditor"
    )

def test_get_account_password_policy_returns_password_policy():
    session = Mock()
    iam_client = Mock()

    iam_client.get_account_password_policy.return_value = {
        "PasswordPolicy": {
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
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.get_account_password_policy()

    assert result == {
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

    iam_client.get_account_password_policy.assert_called_once_with()
