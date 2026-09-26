from unittest.mock import Mock

from scanner.aws.collectors.elb import ELBDataCollector


def test_collects_classic_load_balancer_security_fields():
    service = Mock()

    service.list_classic_load_balancers.return_value = [
        {
            "LoadBalancerName": "classic-prod",
            "AvailabilityZones": [
                "us-east-1a",
                "us-east-1b",
            ],
            "SecurityGroups": [
                "sg-123",
            ],
            "ListenerDescriptions": [
                {
                    "Listener": {
                        "Protocol": "HTTPS",
                        "LoadBalancerPort": 443,
                        "InstanceProtocol": "HTTP",
                        "InstancePort": 80,
                        "SSLCertificateId": (
                            "arn:aws:acm:us-east-1:123:"
                            "certificate/test"
                        ),
                    },
                    "PolicyNames": [
                        "ELBSecurityPolicy-TLS-1-2-2017-01"
                    ],
                },
            ],
        },
    ]

    service.describe_classic_load_balancer_attributes.return_value = {
        "ConnectionDraining": {
            "Enabled": True,
        },
        "CrossZoneLoadBalancing": {
            "Enabled": True,
        },
        "AccessLog": {
            "Enabled": True,
        },
        "AdditionalAttributes": [
            {
                "Key": "elb.http.desyncmitigationmode",
                "Value": "defensive",
            },
        ],
    }

    service.list_load_balancers.return_value = []

    collector = ELBDataCollector(service)

    result = collector.collect_load_balancers()

    assert result == [
        {
            "resource_id": "classic-prod",
            "resource_type": "classic_load_balancer",
            "resource_arn": None,
            "name": "classic-prod",
            "type": "classic",
            "scheme": None,
            "state": None,
            "availability_zones": [
                "us-east-1a",
                "us-east-1b",
            ],
            "security_groups": [
                "sg-123",
            ],
            "listeners": [
                {
                    "resource_id": "classic-listener:443",
                    "resource_type": "classic_elb_listener",
                    "protocol": "HTTPS",
                    "port": 443,
                    "instance_protocol": "HTTP",
                    "instance_port": 80,
                    "ssl_certificate_id": (
                        "arn:aws:acm:us-east-1:123:"
                        "certificate/test"
                    ),
                    "policy_names": [
                        "ELBSecurityPolicy-TLS-1-2-2017-01"
                    ],
                },
            ],
            "target_groups": [],
            "attributes": {
                "ConnectionDraining": {
                    "Enabled": True,
                },
                "CrossZoneLoadBalancing": {
                    "Enabled": True,
                },
                "AccessLog": {
                    "Enabled": True,
                },
                "AdditionalAttributes": [
                    {
                        "Key": (
                            "elb.http.desyncmitigationmode"
                        ),
                        "Value": "defensive",
                    },
                ],
            },
            "deletion_protection": None,
            "access_logs_enabled": True,
            "drop_invalid_headers": None,
            "desync_mitigation_mode": "defensive",
            "connection_draining_enabled": True,
            "cross_zone_load_balancing_enabled": True,
            "waf_web_acl_arn": None,
        }
    ]


def test_collects_v2_waf_policy_and_target_type():
    service = Mock()

    service.list_classic_load_balancers.return_value = []

    service.list_load_balancers.return_value = [
        {
            "LoadBalancerArn": "arn:alb",
            "LoadBalancerName": "prod",
            "Type": "application",
            "AvailabilityZones": [
                {"ZoneName": "us-east-1a"},
                {"ZoneName": "us-east-1b"},
            ],
        }
    ]

    service.list_listeners.return_value = [
        {
            "ListenerArn": "arn:listener",
            "Protocol": "HTTPS",
            "Port": 443,
            "SslPolicy": (
                "ELBSecurityPolicy-TLS13-1-3-2021-06"
            ),
            "DefaultActions": [],
        }
    ]

    service.list_target_groups.return_value = [
        {
            "TargetGroupArn": "arn:tg",
            "Protocol": "HTTPS",
            "Port": 443,
            "ProtocolVersion": "HTTP1",
            "TargetType": "instance",
            "HealthCheckProtocol": "HTTPS",
        }
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
                "routing.http.drop_invalid_header_fields.enabled"
            ),
            "Value": "true",
        },
        {
            "Key": (
                "routing.http.desync_mitigation_mode"
            ),
            "Value": "strictest",
        },
    ]

    service.get_web_acl_for_resource.return_value = {
        "ARN": "arn:aws:wafv2:region:123:regional/webacl/test/id",
    }

    collector = ELBDataCollector(service)

    result = collector.collect_load_balancers()

    assert result[0]["waf_web_acl_arn"].startswith(
        "arn:aws:wafv2:"
    )
    assert result[0]["listeners"][0]["ssl_policy"] == (
        "ELBSecurityPolicy-TLS13-1-3-2021-06"
    )
    assert result[0]["target_groups"][0]["target_type"] == (
        "instance"
    )


def test_collector_caches_classic_and_v2_data():
    service = Mock()

    service.list_classic_load_balancers.return_value = [
        {
            "LoadBalancerName": "classic",
            "AvailabilityZones": [],
            "ListenerDescriptions": [],
        }
    ]

    service.describe_classic_load_balancer_attributes.return_value = {}

    service.list_load_balancers.return_value = [
        {
            "LoadBalancerArn": "arn:lb",
            "Type": "network",
            "AvailabilityZones": [],
        }
    ]

    service.list_listeners.return_value = []
    service.list_target_groups.return_value = []
    service.describe_load_balancer_attributes.return_value = []

    collector = ELBDataCollector(service)

    collector.collect_load_balancers()
    collector.collect_load_balancers()

    service.list_classic_load_balancers.assert_called_once()
    service.describe_classic_load_balancer_attributes.assert_called_once_with(
        "classic"
    )
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
