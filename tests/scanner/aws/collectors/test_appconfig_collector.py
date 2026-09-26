from unittest.mock import Mock

from scanner.aws.collectors.appconfig import (
    AppConfigDataCollector,
)


ACCOUNT_ID = "123456789012"
REGION = "ap-south-1"


def make_service():
    service = Mock()

    service.application_arn.side_effect = (
        lambda app_id:
        f"arn:aws:appconfig:{REGION}:{ACCOUNT_ID}:"
        f"application/{app_id}"
    )

    service.configuration_profile_arn.side_effect = (
        lambda app_id, profile_id:
        f"arn:aws:appconfig:{REGION}:{ACCOUNT_ID}:"
        f"application/{app_id}/configurationprofile/"
        f"{profile_id}"
    )

    service.environment_arn.side_effect = (
        lambda app_id, environment_id:
        f"arn:aws:appconfig:{REGION}:{ACCOUNT_ID}:"
        f"application/{app_id}/environment/"
        f"{environment_id}"
    )

    service.extension_association_arn.side_effect = (
        lambda association_id:
        f"arn:aws:appconfig:{REGION}:{ACCOUNT_ID}:"
        f"extensionassociation/{association_id}"
    )

    return service


def test_collect_applications_normalizes_tags():
    service = make_service()

    service.list_applications.return_value = [
        {
            "Id": "app1",
            "Name": "payments",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
        "Owner": "security",
        "aws:createdBy": "system",
    }

    result = AppConfigDataCollector(
        service
    ).collect_applications()

    assert result == [
        {
            "application_id": "app1",
            "resource_name": "payments",
            "resource_arn": (
                "arn:aws:appconfig:ap-south-1:"
                "123456789012:application/app1"
            ),
            "resource_type": "appconfig_application",
            "tags": {
                "Environment": "prod",
                "Owner": "security",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collect_applications_detects_system_only_tags():
    service = make_service()

    service.list_applications.return_value = [
        {
            "Id": "app1",
            "Name": "payments",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "aws:createdBy": "system",
    }

    result = AppConfigDataCollector(
        service
    ).collect_applications()

    assert result[0]["tags"] == {}
    assert result[0]["tag_data_available"] is True
    assert result[0]["has_non_system_tags"] is False


def test_collect_configuration_profiles_discovers_profiles():
    service = make_service()

    service.list_applications.return_value = [
        {
            "Id": "app1",
            "Name": "payments",
        }
    ]

    service.list_configuration_profiles.return_value = [
        {
            "Id": "profile1",
            "Name": "production",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
    }

    result = AppConfigDataCollector(
        service
    ).collect_configuration_profiles()

    assert result == [
        {
            "configuration_profile_id": "profile1",
            "application_id": "app1",
            "resource_name": "production",
            "resource_arn": (
                "arn:aws:appconfig:ap-south-1:"
                "123456789012:application/app1/"
                "configurationprofile/profile1"
            ),
            "resource_type": (
                "appconfig_configuration_profile"
            ),
            "tags": {
                "Environment": "prod",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collect_environments_discovers_environments():
    service = make_service()

    service.list_applications.return_value = [
        {
            "Id": "app1",
            "Name": "payments",
        }
    ]

    service.list_environments.return_value = [
        {
            "Id": "env1",
            "Name": "production",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
    }

    result = AppConfigDataCollector(
        service
    ).collect_environments()

    assert result == [
        {
            "environment_id": "env1",
            "application_id": "app1",
            "resource_name": "production",
            "resource_arn": (
                "arn:aws:appconfig:ap-south-1:"
                "123456789012:application/app1/"
                "environment/env1"
            ),
            "resource_type": "appconfig_environment",
            "tags": {
                "Environment": "prod",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collect_extension_associations():
    service = make_service()

    service.list_extension_associations.return_value = [
        {
            "Id": "assoc1",
            "ExtensionArn": "arn:extension:one",
            "ResourceArn": "arn:resource:one",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Owner": "security",
    }

    result = AppConfigDataCollector(
        service
    ).collect_extension_associations()

    assert result == [
        {
            "association_id": "assoc1",
            "extension_arn": "arn:extension:one",
            "associated_resource_arn": "arn:resource:one",
            "resource_name": "assoc1",
            "resource_arn": (
                "arn:aws:appconfig:ap-south-1:"
                "123456789012:extensionassociation/assoc1"
            ),
            "resource_type": (
                "appconfig_extension_association"
            ),
            "tags": {
                "Owner": "security",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collector_caches_application_discovery():
    service = make_service()

    service.list_applications.return_value = []
    service.list_configuration_profiles.return_value = []
    service.list_environments.return_value = []

    collector = AppConfigDataCollector(service)

    assert collector.collect_applications() == []
    assert collector.collect_applications() == []

    assert collector.collect_configuration_profiles() == []
    assert collector.collect_environments() == []

    service.list_applications.assert_called_once()


def test_collector_skips_invalid_resources():
    service = make_service()

    service.list_applications.return_value = [
        {
            "Id": "app1",
            "Name": "valid",
        },
        {
            "Id": "",
            "Name": "invalid",
        },
        None,
    ]

    service.list_tags_for_resource.return_value = {}

    result = AppConfigDataCollector(
        service
    ).collect_applications()

    assert len(result) == 1
    assert result[0]["resource_name"] == "valid"
