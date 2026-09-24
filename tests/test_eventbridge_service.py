from unittest.mock import Mock

from scanner.aws.services.eventbridge import (
    EventBridgeService,
)


EVENT_BUS_ARN = (
    "arn:aws:events:region:account:"
    "event-bus:test-bus"
)

ENDPOINT_ARN = (
    "arn:aws:events:region:account:"
    "endpoint:test-endpoint"
)


def test_list_event_buses_collects_all_pages():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    paginator = Mock()
    client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "EventBuses": [
                {
                    "Arn": EVENT_BUS_ARN,
                    "Name": "test-bus",
                }
            ]
        },
        {
            "EventBuses": [
                {
                    "Arn": (
                        "arn:aws:events:region:account:"
                        "event-bus:second"
                    ),
                    "Name": "second",
                }
            ]
        },
    ]

    service = EventBridgeService(session)

    result = service.list_event_buses()

    assert len(result) == 2
    assert result[0]["Arn"] == EVENT_BUS_ARN


def test_describe_event_bus_returns_policy():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.describe_event_bus.return_value = {
        "Arn": EVENT_BUS_ARN,
        "Name": "test-bus",
        "Description": "test",
        "Policy": (
            '{"Version":"2012-10-17",'
            '"Statement":[]}'
        ),
    }

    service = EventBridgeService(session)

    result = service.describe_event_bus("test-bus")

    assert result["arn"] == EVENT_BUS_ARN
    assert result["name"] == "test-bus"
    assert result["policy"] == {
        "Version": "2012-10-17",
        "Statement": [],
    }

    client.describe_event_bus.assert_called_once_with(
        Name="test-bus",
    )


def test_list_event_bus_tags_returns_tags():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    client.list_tags_for_resource.return_value = {
        "Tags": [
            {
                "Key": "Environment",
                "Value": "prod",
            }
        ]
    }

    service = EventBridgeService(session)

    result = service.list_event_bus_tags(EVENT_BUS_ARN)

    assert result == [
        {
            "Key": "Environment",
            "Value": "prod",
        }
    ]

    client.list_tags_for_resource.assert_called_once_with(
        ResourceARN=EVENT_BUS_ARN,
    )


def test_list_endpoints_collects_all_pages():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    paginator = Mock()
    client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "Endpoints": [
                {
                    "Arn": ENDPOINT_ARN,
                    "Name": "test-endpoint",
                    "State": "ACTIVE",
                    "ReplicationConfig": {
                        "State": "ENABLED",
                    },
                }
            ]
        }
    ]

    service = EventBridgeService(session)

    result = service.list_endpoints()

    assert result == [
        {
            "Arn": ENDPOINT_ARN,
            "Name": "test-endpoint",
            "State": "ACTIVE",
            "ReplicationConfig": {
                "State": "ENABLED",
            },
        }
    ]
