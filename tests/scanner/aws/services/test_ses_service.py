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
                {"ContactListName": "marketing"},
            ],
            "NextToken": "next",
        },
        {
            "ContactLists": [
                {"ContactListName": "security"},
            ],
        },
    ]

    result = service.list_contact_lists()

    assert result == [
        {"ContactListName": "marketing"},
        {"ContactListName": "security"},
    ]

    assert client.list_contact_lists.call_count == 2
    assert client.list_contact_lists.call_args_list[1].kwargs[
        "NextToken"
    ] == "next"


def test_get_contact_list_returns_metadata():
    service, client = make_service()

    client.get_contact_list.return_value = {
        "ContactListName": "marketing",
        "Tags": [
            {"Key": "Environment", "Value": "prod"},
        ],
    }

    result = service.get_contact_list("marketing")

    assert result["ContactListName"] == "marketing"
    assert result["Tags"] == [
        {"Key": "Environment", "Value": "prod"},
    ]


def test_list_configuration_sets_paginates():
    service, client = make_service()

    client.list_configuration_sets.side_effect = [
        {
            "ConfigurationSets": ["primary"],
            "NextToken": "next",
        },
        {
            "ConfigurationSets": ["secondary"],
        },
    ]

    result = service.list_configuration_sets()

    assert result == [
        "primary",
        "secondary",
    ]

    assert client.list_configuration_sets.call_count == 2


def test_get_configuration_set_returns_configuration():
    service, client = make_service()

    client.get_configuration_set.return_value = {
        "ConfigurationSetName": "primary",
        "Tags": [
            {"Key": "Environment", "Value": "prod"},
        ],
        "DeliveryOptions": {
            "TlsPolicy": "REQUIRE",
        },
    }

    result = service.get_configuration_set("primary")

    assert result["ConfigurationSetName"] == "primary"
    assert result["DeliveryOptions"]["TlsPolicy"] == "REQUIRE"


def test_service_wraps_client_error():
    service, client = make_service()

    error = Mock()
    error.response = {
        "Error": {
            "Code": "AccessDeniedException",
            "Message": "Access denied",
        }
    }

    from botocore.exceptions import ClientError

    client.list_contact_lists.side_effect = ClientError(
        error.response,
        "ListContactLists",
    )

    with pytest.raises(
        RuntimeError,
        match="SES contact-list discovery failed",
    ):
        service.list_contact_lists()
