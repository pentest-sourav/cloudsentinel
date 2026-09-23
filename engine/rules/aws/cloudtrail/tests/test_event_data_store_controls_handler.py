from unittest.mock import Mock

from engine.rules.aws.cloudtrail.handlers import (
    collect_cloudtrail_event_data_stores,
)


EVENT_DATA_STORE_ARN = (
    "arn:aws:cloudtrail:eu-north-1:"
    "123456789012:eventdatastore/"
    "11111111-2222-3333-4444-555555555555"
)


def test_event_data_store_handler_normalizes_all_ct013_ct016_fields():
    collector = Mock()

    collector.get_event_data_stores.return_value = [
        {
            "EventDataStoreArn": EVENT_DATA_STORE_ARN,
            "Name": "security-events",
            "Status": "ENABLED",
            "KmsKeyId": "arn:aws:kms:eu-north-1:123456789012:key/example",
            "MultiRegionEnabled": True,
            "OrganizationEnabled": True,
            "RetentionPeriod": 365,
            "TerminationProtectionEnabled": True,
            "AdvancedEventSelectors": [
                {
                    "Name": "Management events selector",
                    "FieldSelectors": [
                        {
                            "Field": "eventCategory",
                            "Equals": ["Management"],
                        }
                    ],
                }
            ],
        }
    ]

    result = collect_cloudtrail_event_data_stores(collector)

    assert result == [
        {
            "event_data_store_arn": EVENT_DATA_STORE_ARN,
            "name": "security-events",
            "kms_key_id": (
                "arn:aws:kms:eu-north-1:"
                "123456789012:key/example"
            ),
            "status": "ENABLED",
            "multi_region_enabled": True,
            "organization_enabled": True,
            "retention_period": 365,
            "termination_protection_enabled": True,
            "management_events_enabled": True,
        }
    ]

    collector.get_event_data_stores.assert_called_once()


def test_event_data_store_handler_defaults_empty_selectors_to_management_events():
    collector = Mock()

    collector.get_event_data_stores.return_value = [
        {
            "EventDataStoreArn": EVENT_DATA_STORE_ARN,
            "Name": "security-events",
            "Status": "CREATED",
            "AdvancedEventSelectors": [],
        }
    ]

    result = collect_cloudtrail_event_data_stores(collector)

    assert result[0]["management_events_enabled"] is True


def test_event_data_store_handler_detects_missing_management_events():
    collector = Mock()

    collector.get_event_data_stores.return_value = [
        {
            "EventDataStoreArn": EVENT_DATA_STORE_ARN,
            "Name": "security-events",
            "Status": "ENABLED",
            "AdvancedEventSelectors": [
                {
                    "Name": "Data events selector",
                    "FieldSelectors": [
                        {
                            "Field": "eventCategory",
                            "Equals": ["Data"],
                        }
                    ],
                }
            ],
        }
    ]

    result = collect_cloudtrail_event_data_stores(collector)

    assert result[0]["management_events_enabled"] is False


def test_event_data_store_handler_skips_entries_without_arn():
    collector = Mock()

    collector.get_event_data_stores.return_value = [
        {
            "Name": "invalid-store",
            "Status": "ENABLED",
        },
        {
            "EventDataStoreArn": EVENT_DATA_STORE_ARN,
            "Name": "valid-store",
            "Status": "ENABLED",
        },
    ]

    result = collect_cloudtrail_event_data_stores(collector)

    assert len(result) == 1
    assert result[0]["event_data_store_arn"] == EVENT_DATA_STORE_ARN
