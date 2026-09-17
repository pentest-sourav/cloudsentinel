from unittest.mock import Mock

from scanner.aws.collectors.iam import IAMDataCollector


def test_collect_root_mfa():
    service = Mock()
    service.get_root_mfa_status.return_value = True

    collector = IAMDataCollector(service)

    result = collector.collect_root_mfa()

    assert result == {
        "root_mfa_enabled": True,
    }

    service.get_root_mfa_status.assert_called_once()


def test_collect_iam_users():
    service = Mock()

    service.list_users.return_value = [
        {"UserName": "alice"},
        {"UserName": "bob"},
    ]

    service.list_mfa_devices.side_effect = [
        [{"SerialNumber": "mfa-alice"}],
        [],
    ]

    collector = IAMDataCollector(service)

    result = collector.collect_iam_users()

    assert result == [
        {
            "username": "alice",
            "mfa_devices": [
                {"SerialNumber": "mfa-alice"},
            ],
        },
        {
            "username": "bob",
            "mfa_devices": [],
        },
    ]

    service.list_users.assert_called_once()
    assert service.list_mfa_devices.call_count == 2
