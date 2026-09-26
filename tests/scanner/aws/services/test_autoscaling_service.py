from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.autoscaling import (
    AutoScalingService,
)


def make_service():
    session = Mock()
    session.region_name = "ap-south-1"

    client = Mock()

    service = AutoScalingService(
        session,
        account_id="123456789012",
        region_name="ap-south-1",
    )

    service.autoscaling_client = client

    return service, client


def test_list_auto_scaling_groups_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "AutoScalingGroups": [
                {"AutoScalingGroupName": "one"},
            ],
        },
        {
            "AutoScalingGroups": [
                {"AutoScalingGroupName": "two"},
            ],
        },
    ]

    client.get_paginator.return_value = paginator

    assert service.list_auto_scaling_groups() == [
        {"AutoScalingGroupName": "one"},
        {"AutoScalingGroupName": "two"},
    ]

    client.get_paginator.assert_called_once_with(
        "describe_auto_scaling_groups"
    )


def test_list_launch_configurations_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "LaunchConfigurations": [
                {
                    "LaunchConfigurationName": "legacy",
                },
            ],
        },
    ]

    client.get_paginator.return_value = paginator

    assert service.list_launch_configurations(
        ["legacy"]
    ) == [
        {
            "LaunchConfigurationName": "legacy",
        },
    ]

    paginator.paginate.assert_called_once_with(
        LaunchConfigurationNames=["legacy"]
    )


def test_launch_configuration_names_are_batched_at_50():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.side_effect = [
        [
            {
                "LaunchConfigurations": [
                    {"LaunchConfigurationName": "one"},
                ],
            }
        ],
        [
            {
                "LaunchConfigurations": [
                    {"LaunchConfigurationName": "two"},
                ],
            }
        ],
    ]

    client.get_paginator.return_value = paginator

    names = [
        f"config-{index}"
        for index in range(51)
    ]

    result = service.list_launch_configurations(names)

    assert result == [
        {"LaunchConfigurationName": "one"},
        {"LaunchConfigurationName": "two"},
    ]

    assert paginator.paginate.call_count == 2
    assert len(
        paginator.paginate.call_args_list[0].kwargs[
            "LaunchConfigurationNames"
        ]
    ) == 50
    assert len(
        paginator.paginate.call_args_list[1].kwargs[
            "LaunchConfigurationNames"
        ]
    ) == 1


def test_aws_client_error_is_normalized():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            },
        },
        "DescribeAutoScalingGroups",
    )

    client.get_paginator.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.list_auto_scaling_groups()
