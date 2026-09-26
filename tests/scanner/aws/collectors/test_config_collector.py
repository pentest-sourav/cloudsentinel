from unittest.mock import Mock

from scanner.aws.collectors.config import ConfigDataCollector


def test_collect_recorders_normalizes_recorder_and_status():
    service = Mock()

    service.describe_configuration_recorders.return_value = [
        {
            "name": "default",
            "roleARN": (
                "arn:aws:iam::123456789012:"
                "role/AWSServiceRoleForConfig"
            ),
            "servicePrincipal": "config.amazonaws.com",
            "recordingGroup": {
                "allSupported": True,
                "includeGlobalResourceTypes": True,
                "resourceTypes": [],
                "recordingStrategy": {
                    "useOnly": "ALL_SUPPORTED_RESOURCE_TYPES",
                },
            },
        }
    ]

    service.describe_configuration_recorder_status.return_value = [
        {
            "name": "default",
            "recording": True,
            "lastStatus": "SUCCESS",
        }
    ]

    collector = ConfigDataCollector(service)

    result = collector.collect_recorders()

    assert result == [
        {
            "name": "default",
            "role_arn": (
                "arn:aws:iam::123456789012:"
                "role/AWSServiceRoleForConfig"
            ),
            "service_principal": "config.amazonaws.com",
            "recording": True,
            "last_status": "SUCCESS",
            "last_error_code": None,
            "last_error_message": None,
            "all_supported": True,
            "include_global_resource_types": True,
            "resource_types": [],
            "recording_strategy": (
                "ALL_SUPPORTED_RESOURCE_TYPES"
            ),
            "recording_group": {
                "allSupported": True,
                "includeGlobalResourceTypes": True,
                "resourceTypes": [],
                "recordingStrategy": {
                    "useOnly": (
                        "ALL_SUPPORTED_RESOURCE_TYPES"
                    ),
                },
            },
        }
    ]


def test_collect_recorders_caches_api_calls():
    service = Mock()

    service.describe_configuration_recorders.return_value = [
        {"name": "default"}
    ]

    service.describe_configuration_recorder_status.return_value = [
        {
            "name": "default",
            "recording": True,
        }
    ]

    collector = ConfigDataCollector(service)

    first = collector.collect_recorders()
    second = collector.collect_recorders()

    assert first == second

    service.describe_configuration_recorders.assert_called_once()
    service.describe_configuration_recorder_status.assert_called_once()


def test_collect_account_detects_no_configuration_recorder():
    service = Mock()

    service.describe_configuration_recorders.return_value = []
    service.describe_configuration_recorder_status.return_value = []

    collector = ConfigDataCollector(service)

    assert collector.collect_account() == {
        "recorder_count": 0,
        "active_recorder_count": 0,
        "recorder_names": [],
        "active_recorder_names": [],
    }


def test_collect_account_detects_active_recorder():
    service = Mock()

    service.describe_configuration_recorders.return_value = [
        {
            "name": "default",
            "roleARN": (
                "arn:aws:iam::123456789012:"
                "role/AWSServiceRoleForConfig"
            ),
        }
    ]

    service.describe_configuration_recorder_status.return_value = [
        {
            "name": "default",
            "recording": True,
        }
    ]

    collector = ConfigDataCollector(service)

    assert collector.collect_account() == {
        "recorder_count": 1,
        "active_recorder_count": 1,
        "recorder_names": ["default"],
        "active_recorder_names": ["default"],
    }
