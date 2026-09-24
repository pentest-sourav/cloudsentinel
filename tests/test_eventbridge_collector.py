from unittest.mock import Mock

from scanner.aws.collectors.eventbridge import (
    EventBridgeDataCollector,
)


EVENT_BUS_ARN = (
    "arn:aws:events:region:account:"
    "event-bus:test-bus"
)

ENDPOINT_ARN = (
    "arn:aws:events:region:account:"
    "endpoint:test-endpoint"
)


def test_collect_event_buses_normalizes_security_data():
    service = Mock()

    service.list_event_buses.return_value = [
        {
            "Arn": EVENT_BUS_ARN,
            "Name": "test-bus",
        }
    ]

    service.describe_event_bus.return_value = {
        "arn": EVENT_BUS_ARN,
        "name": "test-bus",
        "description": "test",
        "event_source_name": None,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [],
        },
    }

    service.list_event_bus_tags.return_value = [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]

    collector = EventBridgeDataCollector(service)

    result = collector.collect_event_buses()

    assert result == [
        {
            "event_bus_arn": EVENT_BUS_ARN,
            "name": "test-bus",
            "description": "test",
            "event_source_name": None,
            "policy": {
                "Version": "2012-10-17",
                "Statement": [],
            },
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        }
    ]


def test_collect_endpoints_normalizes_replication_configuration():
    service = Mock()

    service.list_endpoints.return_value = [
        {
            "Arn": ENDPOINT_ARN,
            "Name": "test-endpoint",
            "State": "ACTIVE",
            "ReplicationConfig": {
                "State": "ENABLED",
            },
            "EventBuses": [
                {
                    "EventBusArn": EVENT_BUS_ARN,
                }
            ],
        }
    ]

    collector = EventBridgeDataCollector(service)

    result = collector.collect_endpoints()

    assert result == [
        {
            "endpoint_arn": ENDPOINT_ARN,
            "name": "test-endpoint",
            "state": "ACTIVE",
            "replication_config": {
                "State": "ENABLED",
            },
            "event_buses": [
                {
                    "EventBusArn": EVENT_BUS_ARN,
                }
            ],
        }
    ]


def test_collector_caches_event_bus_data():
    service = Mock()

    service.list_event_buses.return_value = [
        {
            "Arn": EVENT_BUS_ARN,
            "Name": "test-bus",
        }
    ]

    service.describe_event_bus.return_value = {
        "arn": EVENT_BUS_ARN,
        "name": "test-bus",
        "event_source_name": None,
        "policy": None,
    }

    service.list_event_bus_tags.return_value = []

    collector = EventBridgeDataCollector(service)

    collector.collect_event_buses()
    collector.collect_event_buses()

    service.list_event_buses.assert_called_once()
    service.describe_event_bus.assert_called_once_with(
        "test-bus"
    )
    service.list_event_bus_tags.assert_called_once_with(
        EVENT_BUS_ARN
    )


def test_collector_caches_endpoint_data():
    service = Mock()

    service.list_endpoints.return_value = [
        {
            "Arn": ENDPOINT_ARN,
            "Name": "test-endpoint",
            "State": "ACTIVE",
            "ReplicationConfig": {
                "State": "ENABLED",
            },
        }
    ]

    collector = EventBridgeDataCollector(service)

    collector.collect_endpoints()
    collector.collect_endpoints()

    service.list_endpoints.assert_called_once()
