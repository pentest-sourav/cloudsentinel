from unittest.mock import MagicMock

from scanner.aws.services.kms import KMSService


def test_list_keys():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {"Keys": [{"KeyId": "key-1"}]},
        {"Keys": [{"KeyId": "key-2"}]},
    ]

    client.get_paginator.return_value = paginator

    service = KMSService(session)

    assert service.list_keys() == [
        {"KeyId": "key-1"},
        {"KeyId": "key-2"},
    ]


def test_describe_key():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client
    client.describe_key.return_value = {
        "KeyMetadata": {
            "KeyId": "key-1",
            "KeyState": "Enabled",
            "KeyManager": "CUSTOMER",
        }
    }

    service = KMSService(session)

    assert service.describe_key("key-1") == {
        "KeyId": "key-1",
        "KeyState": "Enabled",
        "KeyManager": "CUSTOMER",
    }


def test_get_key_rotation_status():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client
    client.get_key_rotation_status.return_value = {
        "KeyRotationEnabled": True
    }

    service = KMSService(session)

    assert service.get_key_rotation_status("key-1") is True


def test_get_key_policy():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client
    client.get_key_policy.return_value = {
        "Policy": '{"Version":"2012-10-17","Statement":[]}'
    }

    service = KMSService(session)

    assert service.get_key_policy("key-1") == {
        "policy": '{"Version":"2012-10-17","Statement":[]}',
        "policy_name": "default",
    }


def test_list_grants():
    session = MagicMock()
    client = MagicMock()

    session.client.return_value = client

    paginator = MagicMock()
    paginator.paginate.return_value = [
        {
            "Grants": [
                {
                    "GrantId": "grant-1",
                    "Operations": ["Decrypt"],
                }
            ]
        },
        {
            "Grants": [
                {
                    "GrantId": "grant-2",
                    "Operations": ["Encrypt"],
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    service = KMSService(session)

    assert service.list_grants("key-1") == [
        {
            "GrantId": "grant-1",
            "Operations": ["Decrypt"],
        },
        {
            "GrantId": "grant-2",
            "Operations": ["Encrypt"],
        },
    ]

    paginator.paginate.assert_called_once_with(KeyId="key-1")
