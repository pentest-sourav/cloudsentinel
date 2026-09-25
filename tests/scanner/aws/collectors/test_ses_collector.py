from unittest.mock import Mock

from scanner.aws.collectors.ses import SESDataCollector


def test_collect_contact_lists_filters_system_tags():
    service = Mock()

    service.list_contact_lists.return_value = [
        {
            "ContactListName": "marketing",
        },
    ]

    service.get_contact_list.return_value = {
        "ContactListName": "marketing",
        "Tags": [
            {
                "Key": "aws:createdBy",
                "Value": "system",
            },
            {
                "Key": "Environment",
                "Value": "prod",
            },
        ],
    }

    collector = SESDataCollector(service)

    assert collector.collect_contact_lists() == [
        {
            "resource_id": "marketing",
            "resource_type": "ses_contact_list",
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        },
    ]


def test_collect_contact_lists_without_tags():
    service = Mock()

    service.list_contact_lists.return_value = [
        {
            "ContactListName": "marketing",
        },
    ]

    service.get_contact_list.return_value = {
        "ContactListName": "marketing",
        "Tags": [],
    }

    collector = SESDataCollector(service)

    result = collector.collect_contact_lists()

    assert result[0]["tags"] == []


def test_collect_configuration_sets_normalizes_metadata():
    service = Mock()

    service.list_configuration_sets.return_value = [
        "prod",
    ]

    service.get_configuration_set.return_value = {
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

    collector = SESDataCollector(service)

    assert collector.collect_configuration_sets() == [
        {
            "resource_id": "prod",
            "resource_type": "ses_configuration_set",
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
            "tls_policy": "REQUIRE",
        },
    ]


def test_collect_configuration_sets_handles_missing_tls():
    service = Mock()

    service.list_configuration_sets.return_value = [
        "prod",
    ]

    service.get_configuration_set.return_value = {
        "Tags": [],
        "DeliveryOptions": {},
    }

    collector = SESDataCollector(service)

    result = collector.collect_configuration_sets()

    assert result[0]["tls_policy"] is None


def test_collector_caches_metadata():
    service = Mock()

    service.list_contact_lists.return_value = [
        {
            "ContactListName": "marketing",
        },
    ]

    service.get_contact_list.return_value = {
        "Tags": [],
    }

    collector = SESDataCollector(service)

    collector.collect_contact_lists()
    collector.collect_contact_lists()

    service.list_contact_lists.assert_called_once()
    service.get_contact_list.assert_called_once_with(
        "marketing"
    )
