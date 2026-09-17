from unittest.mock import MagicMock

import pytest

from scanner.aws.services.ec2 import EC2Service


def test_describe_instances_collects_all_pages():
    session = MagicMock()
    ec2_client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = ec2_client
    ec2_client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-001",
                            "SecurityGroupIds": [
                                {"GroupId": "sg-001"},
                            ],
                        }
                    ]
                }
            ]
        },
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-002",
                            "SecurityGroupIds": [
                                {"GroupId": "sg-002"},
                            ],
                        }
                    ]
                }
            ]
        },
    ]

    service = EC2Service(session)

    instances = service.describe_instances()

    assert len(instances) == 2
    assert instances[0]["InstanceId"] == "i-001"
    assert instances[1]["InstanceId"] == "i-002"

    ec2_client.get_paginator.assert_called_once_with(
        "describe_instances"
    )


def test_describe_instances_returns_empty_list():
    session = MagicMock()
    ec2_client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = ec2_client
    ec2_client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {"Reservations": []},
    ]

    service = EC2Service(session)

    instances = service.describe_instances()

    assert instances == []


def test_describe_security_groups_returns_groups():
    session = MagicMock()
    ec2_client = MagicMock()

    session.client.return_value = ec2_client

    ec2_client.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-001",
                "GroupName": "web",
            }
        ]
    }

    service = EC2Service(session)

    groups = service.describe_security_groups(
        ["sg-001"]
    )

    assert len(groups) == 1
    assert groups[0]["GroupId"] == "sg-001"

    ec2_client.describe_security_groups.assert_called_once_with(
        GroupIds=["sg-001"]
    )


def test_describe_security_groups_empty_ids():
    session = MagicMock()
    ec2_client = MagicMock()

    session.client.return_value = ec2_client

    service = EC2Service(session)

    groups = service.describe_security_groups([])

    assert groups == []

    ec2_client.describe_security_groups.assert_not_called()


def test_describe_instances_translates_client_error():
    session = MagicMock()
    ec2_client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = ec2_client
    ec2_client.get_paginator.return_value = paginator

    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": "Access denied",
        }
    }

    from botocore.exceptions import ClientError

    paginator.paginate.side_effect = ClientError(
        error_response,
        "DescribeInstances",
    )

    service = EC2Service(session)

    with pytest.raises(
        RuntimeError,
        match="EC2 instance discovery failed",
    ):
        service.describe_instances()
