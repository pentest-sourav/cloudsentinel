from unittest.mock import Mock

from scanner.aws.collectors.ses import SESDataCollector


def test_collect_contact_lists_normalizes_and_ignores_system_tags():
    service = Mock()

    service.list_contact_lists.return_value = [
        {"ContactListName": "marketing"},
    ]

    service.get_contact_list.return_value = {
        "ContactListName": "marketing",
        "Tags": [
            {"Key": "aws:createdBy", "Value": "system"},
            {"Key": "Environment", "Value": "prod"},
        ],
    }

    collector = SESDataCollector(service)

    result = collector.collect_contact_lists()

    assert result == [
        {
            "resource_id": "marketing",
            "resource_type": "ses_contact_list",
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        }
    ]


def test_collect_contact_lists_without_tags():
    service = Mock()

    service.list_contact_lists.return_value = [
        {"ContactListName": "marketing"},
    ]

    service.get_contact_list.return_value = {
        "ContactListName": "marketing",
        "Tags": [],
    }

    collector = SESDataCollector(service)

    result = collector.collect_contact_lists()

    assert result[0]["tags"] == []


def test_collect_configuration_sets_normalizes_tags_and_tls():
    service = Mock()

    service.list_configuration_sets.return_value = [
        "primary",
    ]

    service.get_configuration_set.return_value = {
        "ConfigurationSetName": "primary",
        "Tags": [
            {"Key": "aws:system", "Value": "x"},
            {"Key": "Environment", "Value": "prod"},
        ],
        "DeliveryOptions": {
            "TlsPolicy": "REQUIRE",
        },
    }

    collector = SESDataCollector(service)

    result = collector.collect_configuration_sets()

    assert result == [
        {
            "resource_id": "primary",
            "resource_type": "ses_configuration_set",
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
            "tls_policy": "REQUIRE",
        }
    ]
