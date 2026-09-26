from unittest.mock import Mock

import pytest

from scanner.aws.services.elb import ELBService


def make_service():
    session = Mock()

    clients = {
        "elb": Mock(),
        "elbv2": Mock(),
        "wafv2": Mock(),
    }

    def client(name, **kwargs):
        return clients[name]

    session.client.side_effect = client

    service = ELBService(session)

    return service, clients


def test_list_classic_load_balancers_uses_paginator():
    service, clients = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "LoadBalancerDescriptions": [
                {"LoadBalancerName": "classic-1"},
            ],
        },
        {
            "LoadBalancerDescriptions": [
                {"LoadBalancerName": "classic-2"},
            ],
        },
    ]

    clients["elb"].get_paginator.return_value = paginator

    assert service.list_classic_load_balancers() == [
        {"LoadBalancerName": "classic-1"},
        {"LoadBalancerName": "classic-2"},
    ]

    clients["elb"].get_paginator.assert_called_once_with(
        "describe_load_balancers"
    )


def test_classic_attributes():
    service, clients = make_service()

    clients["elb"].describe_load_balancer_attributes.return_value = {
        "LoadBalancerAttributes": {
            "ConnectionDraining": {
                "Enabled": True,
            },
            "CrossZoneLoadBalancing": {
                "Enabled": True,
            },
        }
    }

    assert service.describe_classic_load_balancer_attributes(
        "classic"
    ) == {
        "ConnectionDraining": {
            "Enabled": True,
        },
        "CrossZoneLoadBalancing": {
            "Enabled": True,
        },
    }


def test_list_load_balancers_paginates():
    service, clients = make_service()

    clients["elbv2"].describe_load_balancers.side_effect = [
        {
            "LoadBalancers": [
                {"LoadBalancerArn": "arn:lb:1"},
            ],
            "NextMarker": "next",
        },
        {
            "LoadBalancers": [
                {"LoadBalancerArn": "arn:lb:2"},
            ],
        },
    ]

    assert service.list_load_balancers() == [
        {"LoadBalancerArn": "arn:lb:1"},
        {"LoadBalancerArn": "arn:lb:2"},
    ]


def test_list_listeners_paginates():
    service, clients = make_service()

    clients["elbv2"].describe_listeners.side_effect = [
        {
            "Listeners": [
                {"ListenerArn": "arn:listener:1"},
            ],
            "NextMarker": "next",
        },
        {
            "Listeners": [
                {"ListenerArn": "arn:listener:2"},
            ],
        },
    ]

    assert service.list_listeners(
        "arn:lb"
    ) == [
        {"ListenerArn": "arn:listener:1"},
        {"ListenerArn": "arn:listener:2"},
    ]


def test_list_target_groups_paginates():
    service, clients = make_service()

    clients["elbv2"].describe_target_groups.side_effect = [
        {
            "TargetGroups": [
                {"TargetGroupArn": "arn:tg:1"},
            ],
            "NextMarker": "next",
        },
        {
            "TargetGroups": [
                {"TargetGroupArn": "arn:tg:2"},
            ],
        },
    ]

    assert service.list_target_groups(
        "arn:lb"
    ) == [
        {"TargetGroupArn": "arn:tg:1"},
        {"TargetGroupArn": "arn:tg:2"},
    ]


def test_describe_attributes():
    service, clients = make_service()

    clients["elbv2"].describe_load_balancer_attributes.return_value = {
        "Attributes": [
            {
                "Key": "deletion_protection.enabled",
                "Value": "true",
            },
        ],
    }

    assert service.describe_load_balancer_attributes(
        "arn:lb"
    ) == [
        {
            "Key": "deletion_protection.enabled",
            "Value": "true",
        },
    ]


def test_get_web_acl_for_resource():
    service, clients = make_service()

    clients["wafv2"].get_web_acl_for_resource.return_value = {
        "WebACL": {
            "ARN": "arn:aws:wafv2:region:123:regional/webacl/test/id",
            "Name": "test",
        }
    }

    assert service.get_web_acl_for_resource(
        "arn:alb"
    ) == {
        "ARN": "arn:aws:wafv2:region:123:regional/webacl/test/id",
        "Name": "test",
    }


def test_get_web_acl_for_resource_returns_none_without_association():
    service, clients = make_service()

    clients["wafv2"].get_web_acl_for_resource.return_value = {
        "WebACL": None,
    }

    assert service.get_web_acl_for_resource(
        "arn:alb"
    ) is None


def test_service_wraps_client_error():
    service, clients = make_service()

    from botocore.exceptions import ClientError

    clients["elbv2"].describe_load_balancers.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "DescribeLoadBalancers",
    )

    with pytest.raises(
        RuntimeError,
        match="AWS ELB load-balancer discovery failed",
    ):
        service.list_load_balancers()
