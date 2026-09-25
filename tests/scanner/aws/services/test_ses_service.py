from unittest.mock import Mock

import pytest

from scanner.aws.services.ses import SESService


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = SESService(session)

    return service, client


def test_list_contact_lists_paginates():
    service, client = make_service()

    client.list_contact_lists.side_effect = [
        {
            "ContactLists": [
                {
                    "ContactListName": "marketing",
                },
            ],
            "NextToken": "next",
        },
        {
            "ContactLists": [
                {
                    "ContactListName": "security",
                },
            ],
        },
    ]

    result = service.list_contact_lists()

    assert result == [
        {
            "ContactListName": "marketing",
        },
        {
            "ContactListName": "security",
        },
    ]

    assert client.list_contact_lists.call_count == 2
    assert (
        client.list_contact_lists.call_args_list[1]
        .kwargs["NextToken"]
        == "next"
    )


def test_get_contact_list_returns_metadata():
    service, client = make_service()

    client.get_contact_list.return_value = {
        "ContactListName": "marketing",
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            },
        ],
    }

    assert service.get_contact_list(
        "marketing"
    ) == {
        "ContactListName": "marketing",
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            },
        ],
    }


def test_list_configuration_sets_paginates():
    service, client = make_service()

    client.list_configuration_sets.side_effect = [
        {
            "ConfigurationSets": [
                "default",
                "prod",
            ],
            "NextToken": "next",
        },
        {
            "ConfigurationSets": [
                "security",
            ],
        },
    ]

    result = service.list_configuration_sets()

    assert result == [
        "default",
        "prod",
        "security",
    ]

    assert client.list_configuration_sets.call_count == 2
    assert (
        client.list_configuration_sets.call_args_list[1]
        .kwargs["NextToken"]
        == "next"
    )


def test_get_configuration_set_returns_metadata():
    service, client = make_service()

    client.get_configuration_set.return_value = {
        "ConfigurationSetName": "prod",
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            },
        ],
        "DeliveryOptions": {
            "TlsPolicy": "REQUIRE",
        },
    }

    assert service.get_configuration_set(
        "prod"
    ) == {
        "ConfigurationSetName": "prod",
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            },
        ],
        "DeliveryOptions": {
            "TlsPolicy": "REQUIRE",
        },
    }


def test_service_wraps_client_error():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.list_contact_lists.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListContactLists",
    )

    with pytest.raises(
        RuntimeError,
        match="SES contact-list discovery failed",
    ):
        service.list_contact_lists()
