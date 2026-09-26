from unittest.mock import Mock

from scanner.aws.collectors.elb import ELBDataCollector


def test_collect_load_balancers_normalizes_security_fields():
    service = Mock()

    service.list_load_balancers.return_value = [
        {
            "LoadBalancerArn": "arn:aws:elasticloadbalancing:region:123:loadbalancer/app/prod/1",
            "LoadBalancerName": "prod",
            "Type": "application",
            "Scheme": "internet-facing",
            "State": {"Code": "active"},
            "AvailabilityZones": [
                {"ZoneName": "us-east-1a"},
                {"ZoneName": "us-east-1b"},
            ],
        },
    ]

    service.list_listeners.return_value = [
        {
            "ListenerArn": "arn:listener:1",
            "Protocol": "HTTP",
            "Port": 80,
            "DefaultActions": [
                {
                    "Type": "redirect",
                    "RedirectConfig": {
                        "Protocol": "HTTPS",
                    },
                },
            ],
        },
    ]

    service.list_target_groups.return_value = [
        {
            "TargetGroupArn": "arn:tg:1",
            "Protocol": "HTTPS",
            "Port": 443,
            "ProtocolVersion": "HTTP1",
            "HealthCheckProtocol": "HTTPS",
        },
    ]

    service.describe_load_balancer_attributes.return_value = [
        {
            "Key": "deletion_protection.enabled",
            "Value": "true",
        },
        {
            "Key": "access_logs.s3.enabled",
            "Value": "true",
        },
        {
            "Key": (
                "routing.http."
                "drop_invalid_header_fields.enabled"
            ),
            "Value": "true",
        },
        {
            "Key": (
                "routing.http."
                "desync_mitigation_mode"
            ),
            "Value": "strictest",
        },
    ]

    collector = ELBDataCollector(service)

    result = collector.collect_load_balancers()

    assert result == [
        {
            "resource_id": (
                "arn:aws:elasticloadbalancing:region:"
                "123:loadbalancer/app/prod/1"
            ),
            "resource_type": "application_load_balancer",
            "resource_arn": (
                "arn:aws:elasticloadbalancing:region:"
                "123:loadbalancer/app/prod/1"
            ),
            "name": "prod",
            "type": "application",
            "scheme": "internet-facing",
            "state": "active",
            "availability_zones": [
                "us-east-1a",
                "us-east-1b",
            ],
            "security_groups": [],
            "listeners": [
                {
                    "resource_id": "arn:listener:1",
                    "resource_type": "elb_listener",
                    "protocol": "HTTP",
                    "port": 80,
                    "ssl_policy": None,
                    "default_actions": [
                        {
                            "Type": "redirect",
                            "RedirectConfig": {
                                "Protocol": "HTTPS",
                            },
                        },
                    ],
                },
            ],
            "target_groups": [
                {
                    "resource_id": "arn:tg:1",
                    "resource_type": "elb_target_group",
                    "protocol": "HTTPS",
                    "port": 443,
                    "protocol_version": "HTTP1",
                    "health_check_protocol": "HTTPS",
                },
            ],
            "attributes": {
                "deletion_protection.enabled": "true",
                "access_logs.s3.enabled": "true",
                (
                    "routing.http."
                    "drop_invalid_header_fields.enabled"
                ): "true",
                (
                    "routing.http."
                    "desync_mitigation_mode"
                ): "strictest",
            },
            "deletion_protection": True,
            "access_logs_enabled": True,
            "drop_invalid_headers": True,
            "desync_mitigation_mode": "strictest",
        },
    ]


def test_collector_caches_nested_resources():
    service = Mock()

    service.list_load_balancers.return_value = [
        {
            "LoadBalancerArn": "arn:lb",
            "Type": "network",
            "AvailabilityZones": [],
        },
    ]

    service.list_listeners.return_value = []
    service.list_target_groups.return_value = []
    service.describe_load_balancer_attributes.return_value = []

    collector = ELBDataCollector(service)

    collector.collect_load_balancers()
    collector.collect_load_balancers()

    service.list_load_balancers.assert_called_once()
    service.list_listeners.assert_called_once_with(
        "arn:lb"
    )
    service.list_target_groups.assert_called_once_with(
        "arn:lb"
    )
    service.describe_load_balancer_attributes.assert_called_once_with(
        "arn:lb"
    )
