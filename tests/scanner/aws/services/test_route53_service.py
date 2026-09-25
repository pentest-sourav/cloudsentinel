from unittest.mock import Mock

import pytest

from scanner.aws.services.route53 import Route53Service


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = Route53Service(session)

    return service, client


def test_list_health_checks_paginates():
    service, client = make_service()

    client.list_health_checks.side_effect = [
        {
            "HealthChecks": [
                {"Id": "hc-1"},
            ],
            "IsTruncated": True,
            "NextMarker": "marker-2",
        },
        {
            "HealthChecks": [
                {"Id": "hc-2"},
            ],
            "IsTruncated": False,
        },
    ]

    result = service.list_health_checks()

    assert result == [
        {"Id": "hc-1"},
        {"Id": "hc-2"},
    ]

    assert client.list_health_checks.call_count == 2
    assert (
        client.list_health_checks.call_args_list[1]
        .kwargs["Marker"]
        == "marker-2"
    )


def test_list_hosted_zones_paginates():
    service, client = make_service()

    client.list_hosted_zones.side_effect = [
        {
            "HostedZones": [
                {
                    "Id": "/hostedzone/ZONE1",
                    "Name": "example.com.",
                },
            ],
            "IsTruncated": True,
            "NextMarker": "ZONE2",
        },
        {
            "HostedZones": [
                {
                    "Id": "/hostedzone/ZONE2",
                    "Name": "internal.example.com.",
                },
            ],
            "IsTruncated": False,
        },
    ]

    result = service.list_hosted_zones()

    assert result == [
        {
            "Id": "/hostedzone/ZONE1",
            "Name": "example.com.",
        },
        {
            "Id": "/hostedzone/ZONE2",
            "Name": "internal.example.com.",
        },
    ]

    assert client.list_hosted_zones.call_count == 2
    assert (
        client.list_hosted_zones.call_args_list[1]
        .kwargs["Marker"]
        == "ZONE2"
    )


def test_list_tags_for_resource_returns_tags():
    service, client = make_service()

    client.list_tags_for_resource.return_value = {
        "ResourceTagSet": {
            "ResourceId": "hc-1",
            "ResourceType": "healthcheck",
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        },
    }

    result = service.list_tags_for_resource(
        "healthcheck",
        "hc-1",
    )

    assert result == [
        {
            "Key": "Environment",
            "Value": "prod",
        },
    ]


def test_list_query_logging_configs_paginates():
    service, client = make_service()

    client.list_query_logging_configs.side_effect = [
        {
            "QueryLoggingConfigs": [
                {
                    "HostedZoneId": "ZONE1",
                },
            ],
            "NextToken": "next",
        },
        {
            "QueryLoggingConfigs": [
                {
                    "HostedZoneId": "ZONE2",
                },
            ],
        },
    ]

    result = service.list_query_logging_configs()

    assert result == [
        {"HostedZoneId": "ZONE1"},
        {"HostedZoneId": "ZONE2"},
    ]

    assert client.list_query_logging_configs.call_count == 2
    assert (
        client.list_query_logging_configs.call_args_list[1]
        .kwargs["NextToken"]
        == "next"
    )


def test_service_wraps_client_error():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.list_health_checks.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "ListHealthChecks",
    )

    with pytest.raises(
        RuntimeError,
        match="Route 53 health-check discovery failed",
    ):
        service.list_health_checks()
