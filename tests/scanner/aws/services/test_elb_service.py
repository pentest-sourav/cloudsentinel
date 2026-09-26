from unittest.mock import Mock

import pytest

from scanner.aws.services.elb import ELBService


def make_service():
    session = Mock()
    client = Mock()

    session.client.return_value = client

    service = ELBService(session)

    return service, client


def test_list_load_balancers_paginates():
    service, client = make_service()

    client.describe_load_balancers.side_effect = [
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

    assert client.describe_load_balancers.call_count == 2
    assert (
        client.describe_load_balancers.call_args_list[1]
        .kwargs["Marker"]
        == "next"
    )


def test_list_listeners_paginates():
    service, client = make_service()

    client.describe_listeners.side_effect = [
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
    service, client = make_service()

    client.describe_target_groups.side_effect = [
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
    service, client = make_service()

    client.describe_load_balancer_attributes.return_value = {
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


def test_service_wraps_client_error():
    service, client = make_service()

    from botocore.exceptions import ClientError

    client.describe_load_balancers.side_effect = ClientError(
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
