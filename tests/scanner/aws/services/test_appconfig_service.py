from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.appconfig import (
    AppConfigService,
)


ACCOUNT_ID = "123456789012"
REGION = "ap-south-1"


def make_service():
    session = Mock()
    session.region_name = REGION

    client = Mock()

    service = AppConfigService(
        session,
        account_id=ACCOUNT_ID,
        region_name=REGION,
    )
    service.appconfig_client = client

    return service, client


def test_list_applications_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Items": [
                {
                    "Id": "app1",
                    "Name": "payments",
                }
            ]
        },
        {
            "Items": [
                {
                    "Id": "app2",
                    "Name": "frontend",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    assert service.list_applications() == [
        {
            "Id": "app1",
            "Name": "payments",
        },
        {
            "Id": "app2",
            "Name": "frontend",
        },
    ]

    client.get_paginator.assert_called_once_with(
        "list_applications"
    )


def test_list_configuration_profiles_uses_application_id():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Items": [
                {
                    "Id": "profile1",
                    "Name": "production",
                }
            ]
        }
    ]

    client.get_paginator.return_value = paginator

    assert service.list_configuration_profiles(
        "app1"
    ) == [
        {
            "Id": "profile1",
            "Name": "production",
        }
    ]

    client.get_paginator.assert_called_once_with(
        "list_configuration_profiles"
    )

    paginator.paginate.assert_called_once_with(
        ApplicationId="app1"
    )


def test_list_configuration_profiles_returns_empty_for_invalid_id():
    service, client = make_service()

    assert service.list_configuration_profiles("") == []

    client.get_paginator.assert_not_called()


def test_list_environments_uses_application_id():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Items": [
                {
                    "Id": "env1",
                    "Name": "production",
                }
            ]
        }
    ]

    client.get_paginator.return_value = paginator

    assert service.list_environments("app1") == [
        {
            "Id": "env1",
            "Name": "production",
        }
    ]

    client.get_paginator.assert_called_once_with(
        "list_environments"
    )

    paginator.paginate.assert_called_once_with(
        ApplicationId="app1"
    )


def test_list_environments_returns_empty_for_invalid_id():
    service, client = make_service()

    assert service.list_environments("") == []

    client.get_paginator.assert_not_called()


def test_list_extension_associations_collects_results():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "Items": [
                {
                    "Id": "assoc1",
                    "ExtensionArn": "arn:extension:one",
                    "ResourceArn": "arn:resource:one",
                }
            ]
        }
    ]

    client.get_paginator.return_value = paginator

    assert service.list_extension_associations() == [
        {
            "Id": "assoc1",
            "ExtensionArn": "arn:extension:one",
            "ResourceArn": "arn:resource:one",
        }
    ]

    client.get_paginator.assert_called_once_with(
        "list_extension_associations"
    )


def test_list_tags_for_resource_returns_tags():
    service, client = make_service()

    client.list_tags_for_resource.return_value = {
        "Tags": {
            "Environment": "prod",
            "Owner": "security",
        }
    }

    assert service.list_tags_for_resource(
        "arn:resource"
    ) == {
        "Environment": "prod",
        "Owner": "security",
    }

    client.list_tags_for_resource.assert_called_once_with(
        ResourceArn="arn:resource"
    )


def test_list_tags_for_resource_returns_empty_for_invalid_arn():
    service, client = make_service()

    assert service.list_tags_for_resource("") == {}

    client.list_tags_for_resource.assert_not_called()


def test_resource_arn_builders():
    service, _ = make_service()

    assert service.application_arn("app1") == (
        "arn:aws:appconfig:ap-south-1:123456789012:"
        "application/app1"
    )

    assert service.configuration_profile_arn(
        "app1",
        "profile1",
    ) == (
        "arn:aws:appconfig:ap-south-1:123456789012:"
        "application/app1/configurationprofile/profile1"
    )

    assert service.environment_arn(
        "app1",
        "env1",
    ) == (
        "arn:aws:appconfig:ap-south-1:123456789012:"
        "application/app1/environment/env1"
    )

    assert service.extension_association_arn(
        "assoc1"
    ) == (
        "arn:aws:appconfig:ap-south-1:123456789012:"
        "extensionassociation/assoc1"
    )


def test_resource_arn_builder_returns_none_without_account():
    session = Mock()
    session.region_name = REGION

    service = AppConfigService(
        session,
        account_id=None,
        region_name=REGION,
    )

    assert service.application_arn("app1") is None


def test_list_applications_normalizes_client_error():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "ListApplications",
    )

    client.get_paginator.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.list_applications()
