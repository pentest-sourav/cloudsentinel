from unittest.mock import MagicMock

from scanner.aws.collectors.iam import IAMDataCollector


def test_collect_no_active_authentication_credentials():
    collector = IAMDataCollector.__new__(IAMDataCollector)

    collector.collect_credential_report = MagicMock(
        return_value=[
            {
                "username": "alice",
                "password_enabled": False,
            },
            {
                "username": "bob",
                "password_enabled": True,
            },
            {
                "username": "charlie",
                "password_enabled": False,
            },
        ]
    )

    collector.collect_iam_access_keys = MagicMock(
        return_value=[
            {
                "username": "alice",
                "access_key_id": "AKIAALICE01",
                "status": "Active",
            },
            {
                "username": "charlie",
                "access_key_id": "AKIACHARLIE01",
                "status": "Inactive",
            },
            {
                "username": "charlie",
                "access_key_id": "AKIACHARLIE02",
                "status": "Active",
            },
        ]
    )

    result = collector.collect_no_active_authentication_credentials()

    assert result == [
        {
            "username": "alice",
            "password_enabled": False,
            "active_access_key_count": 1,
            "active_access_key_ids": ["AKIAALICE01"],
        },
        {
            "username": "bob",
            "password_enabled": True,
            "active_access_key_count": 0,
            "active_access_key_ids": [],
        },
        {
            "username": "charlie",
            "password_enabled": False,
            "active_access_key_count": 1,
            "active_access_key_ids": ["AKIACHARLIE02"],
        },
    ]

    collector.collect_credential_report.assert_called_once()
    collector.collect_iam_access_keys.assert_called_once()
