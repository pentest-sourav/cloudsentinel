from unittest.mock import Mock

from scanner.aws.services.iam import IAMService


def test_get_account_summary_returns_summary():
    session = Mock()

    iam_client = Mock()
    iam_client.get_account_summary.return_value = {
        "SummaryMap": {
            "AccountMFAEnabled": 1,
            "Users": 3,
        }
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.get_account_summary()

    assert result["AccountMFAEnabled"] == 1
    assert result["Users"] == 3

    iam_client.get_account_summary.assert_called_once_with()


def test_get_root_mfa_status_returns_true_when_enabled():
    session = Mock()

    iam_client = Mock()
    iam_client.get_account_summary.return_value = {
        "SummaryMap": {
            "AccountMFAEnabled": 1,
        }
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    assert service.get_root_mfa_status() is True


def test_get_root_mfa_status_returns_false_when_disabled():
    session = Mock()

    iam_client = Mock()
    iam_client.get_account_summary.return_value = {
        "SummaryMap": {
            "AccountMFAEnabled": 0,
        }
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    assert service.get_root_mfa_status() is False

def test_list_users_returns_users():
    session = Mock()

    iam_client = Mock()
    iam_client.list_users.return_value = {
        "Users": [
            {"UserName": "user-one"},
            {"UserName": "user-two"},
        ]
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_users()

    assert result == [
        {"UserName": "user-one"},
        {"UserName": "user-two"},
    ]

    iam_client.list_users.assert_called_once_with()

def test_list_mfa_devices_returns_devices():
    session = Mock()

    iam_client = Mock()
    iam_client.list_mfa_devices.return_value = {
        "MFADevices": [
            {
                "SerialNumber": "arn:aws:iam::123456789012:mfa/user-one"
            }
        ]
    }

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_mfa_devices("user-one")

    assert result == [
        {
            "SerialNumber": "arn:aws:iam::123456789012:mfa/user-one"
        }
    ]

    iam_client.list_mfa_devices.assert_called_once_with(
        UserName="user-one"
    )
