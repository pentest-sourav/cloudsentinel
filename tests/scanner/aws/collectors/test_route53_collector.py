from unittest.mock import Mock

from scanner.aws.collectors.route53 import (
    Route53DataCollector,
)


def test_collect_health_checks_ignores_system_tags():
    service = Mock()

    service.list_health_checks.return_value = [
        {"Id": "hc-1"},
    ]

    service.list_tags_for_resource.return_value = [
        {
            "Key": "aws:createdBy",
            "Value": "system",
        },
        {
            "Key": "Environment",
            "Value": "prod",
        },
    ]

    collector = Route53DataCollector(service)

    result = collector.collect_health_checks()

    assert result == [
        {
            "resource_id": "hc-1",
            "resource_type": "route53_health_check",
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        },
    ]


def test_collect_health_checks_without_tags():
    service = Mock()

    service.list_health_checks.return_value = [
        {"Id": "hc-1"},
    ]

    service.list_tags_for_resource.return_value = []

    collector = Route53DataCollector(service)

    result = collector.collect_health_checks()

    assert result[0]["tags"] == []


def test_collect_hosted_zones_marks_query_logging():
    service = Mock()

    service.list_hosted_zones.return_value = [
        {
            "Id": "/hostedzone/ZONE1",
            "Name": "example.com.",
            "Config": {
                "PrivateZone": False,
            },
        },
    ]

    service.list_query_logging_configs.return_value = [
        {
            "HostedZoneId": "ZONE1",
        },
    ]

    collector = Route53DataCollector(service)

    result = collector.collect_hosted_zones()

    assert result == [
        {
            "resource_id": "ZONE1",
            "resource_type": "route53_hosted_zone",
            "name": "example.com.",
            "private_zone": False,
            "query_logging_enabled": True,
        },
    ]


def test_collect_hosted_zones_marks_missing_query_logging():
    service = Mock()

    service.list_hosted_zones.return_value = [
        {
            "Id": "/hostedzone/ZONE1",
            "Name": "example.com.",
            "Config": {
                "PrivateZone": False,
            },
        },
    ]

    service.list_query_logging_configs.return_value = []

    collector = Route53DataCollector(service)

    result = collector.collect_hosted_zones()

    assert result[0]["query_logging_enabled"] is False


def test_collect_hosted_zones_skips_private_zones():
    service = Mock()

    service.list_hosted_zones.return_value = [
        {
            "Id": "/hostedzone/PRIVATE1",
            "Name": "internal.example.com.",
            "Config": {
                "PrivateZone": True,
            },
        },
    ]

    service.list_query_logging_configs.return_value = []

    collector = Route53DataCollector(service)

    assert collector.collect_hosted_zones() == []
