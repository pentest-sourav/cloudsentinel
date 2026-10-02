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

def test_list_users_returns_users_across_all_pages():
    session = Mock()

    iam_client = Mock()
    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Users": [
                {"UserName": "user-one"},
            ]
        },
        {
            "Users": [
                {"UserName": "user-two"},
            ]
        },
    ]
    iam_client.get_paginator.return_value = paginator

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_users()

    assert result == [
        {"UserName": "user-one"},
        {"UserName": "user-two"},
    ]

    iam_client.get_paginator.assert_called_once_with(
        "list_users"
    )
    paginator.paginate.assert_called_once_with()

def test_list_mfa_devices_returns_devices_across_all_pages():
    session = Mock()

    iam_client = Mock()
    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "MFADevices": [
                {
                    "SerialNumber": (
                        "arn:aws:iam::123456789012:mfa/user-one"
                    )
                }
            ]
        },
        {
            "MFADevices": [
                {
                    "SerialNumber": (
                        "arn:aws:iam::123456789012:mfa/user-two"
                    )
                }
            ]
        },
    ]
    iam_client.get_paginator.return_value = paginator

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_mfa_devices("user-one")

    assert result == [
        {
            "SerialNumber": (
                "arn:aws:iam::123456789012:mfa/user-one"
            )
        },
        {
            "SerialNumber": (
                "arn:aws:iam::123456789012:mfa/user-two"
            )
        },
    ]

    iam_client.get_paginator.assert_called_once_with(
        "list_mfa_devices"
    )
    paginator.paginate.assert_called_once_with(
        UserName="user-one"
    )


def test_list_access_keys_returns_keys_across_all_pages():
    session = Mock()

    iam_client = Mock()
    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAUSERONE",
                    "Status": "Active",
                }
            ]
        },
        {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAUSERTWO",
                    "Status": "Inactive",
                }
            ]
        },
    ]
    iam_client.get_paginator.return_value = paginator

    session.client.return_value = iam_client

    service = IAMService(session)

    result = service.list_access_keys("user-one")

    assert result == [
        {
            "AccessKeyId": "AKIAUSERONE",
            "Status": "Active",
        },
        {
            "AccessKeyId": "AKIAUSERTWO",
            "Status": "Inactive",
        },
    ]

    iam_client.get_paginator.assert_called_once_with(
        "list_access_keys"
    )
    paginator.paginate.assert_called_once_with(
        UserName="user-one"
    )
