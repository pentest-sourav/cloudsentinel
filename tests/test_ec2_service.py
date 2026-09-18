from unittest.mock import MagicMock
from botocore.exceptions import BotoCoreError, ClientError
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


def test_describe_volumes_returns_volumes():
    service = EC2Service.__new__(EC2Service)

    service.ec2_client = MagicMock()

    service.ec2_client.describe_volumes.return_value = {
        "Volumes": [
            {
                "VolumeId": "vol-001",
                "Encrypted": False,
            },
            {
                "VolumeId": "vol-002",
                "Encrypted": True,
            },
        ]
    }

    volumes = service.describe_volumes(
        ["vol-001", "vol-002"]
    )

    assert volumes == [
        {
            "VolumeId": "vol-001",
            "Encrypted": False,
        },
        {
            "VolumeId": "vol-002",
            "Encrypted": True,
        },
    ]


def test_describe_volumes_batches_large_volume_id_list():
    session = MagicMock()
    ec2_client = MagicMock()

    session.client.return_value = ec2_client

    ec2_client.describe_volumes.side_effect = [
        {
            "Volumes": [
                {
                    "VolumeId": "vol-001",
                    "Encrypted": False,
                }
            ]
        },
        {
            "Volumes": [
                {
                    "VolumeId": "vol-101",
                    "Encrypted": True,
                }
            ]
        },
        {
            "Volumes": [
                {
                    "VolumeId": "vol-201",
                    "Encrypted": False,
                }
            ]
        },
    ]

    service = EC2Service(session)

    volume_ids = [
        f"vol-{index:03d}"
        for index in range(1, 202)
    ]

    volumes = service.describe_volumes(volume_ids)

    assert len(volumes) == 3

    assert ec2_client.describe_volumes.call_count == 3

    first_batch = (
        ec2_client.describe_volumes.call_args_list[0]
    )
    second_batch = (
        ec2_client.describe_volumes.call_args_list[1]
    )
    third_batch = (
        ec2_client.describe_volumes.call_args_list[2]
    )

    assert len(first_batch.kwargs["VolumeIds"]) == 100
    assert len(second_batch.kwargs["VolumeIds"]) == 100
    assert len(third_batch.kwargs["VolumeIds"]) == 1


def test_describe_security_groups_batches_large_group_id_list():
    session = MagicMock()
    ec2_client = MagicMock()

    session.client.return_value = ec2_client

    ec2_client.describe_security_groups.side_effect = [
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-001",
                }
            ]
        },
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-101",
                }
            ]
        },
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-201",
                }
            ]
        },
    ]

    service = EC2Service(session)

    group_ids = [
        f"sg-{index:03d}"
        for index in range(1, 202)
    ]

    groups = service.describe_security_groups(group_ids)

    assert len(groups) == 3

    assert ec2_client.describe_security_groups.call_count == 3

    first_batch = (
        ec2_client.describe_security_groups.call_args_list[0]
    )
    second_batch = (
        ec2_client.describe_security_groups.call_args_list[1]
    )
    third_batch = (
        ec2_client.describe_security_groups.call_args_list[2]
    )

    assert len(first_batch.kwargs["GroupIds"]) == 100
    assert len(second_batch.kwargs["GroupIds"]) == 100
    assert len(third_batch.kwargs["GroupIds"]) == 1

def test_describe_snapshots_returns_snapshots():
    session = MagicMock()
    ec2_client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = ec2_client
    ec2_client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "Snapshots": [
                {
                    "SnapshotId": "snap-001",
                    "VolumeId": "vol-001",
                    "State": "completed",
                },
                {
                    "SnapshotId": "snap-002",
                    "VolumeId": "vol-002",
                    "State": "pending",
                },
            ]
        }
    ]

    service = EC2Service(session)

    snapshots = service.describe_snapshots()

    assert len(snapshots) == 2
    assert snapshots[0]["SnapshotId"] == "snap-001"
    assert snapshots[1]["SnapshotId"] == "snap-002"

    ec2_client.get_paginator.assert_called_once_with(
        "describe_snapshots"
    )

    paginator.paginate.assert_called_once_with(
        OwnerIds=["self"]
    )


def test_describe_snapshots_collects_all_pages():
    session = MagicMock()
    ec2_client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = ec2_client
    ec2_client.get_paginator.return_value = paginator

    paginator.paginate.return_value = [
        {
            "Snapshots": [
                {
                    "SnapshotId": "snap-001",
                }
            ]
        },
        {
            "Snapshots": [
                {
                    "SnapshotId": "snap-002",
                }
            ]
        },
    ]

    service = EC2Service(session)

    snapshots = service.describe_snapshots()

    assert len(snapshots) == 2
    assert snapshots[0]["SnapshotId"] == "snap-001"
    assert snapshots[1]["SnapshotId"] == "snap-002"

def test_describe_snapshots_translates_client_error():
    session = MagicMock()
    ec2_client = MagicMock()
    paginator = MagicMock()

    session.client.return_value = ec2_client
    ec2_client.get_paginator.return_value = paginator

    from botocore.exceptions import ClientError

    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": "Access denied",
        }
    }

    paginator.paginate.side_effect = ClientError(
        error_response,
        "DescribeSnapshots",
    )

    service = EC2Service(session)

    with pytest.raises(
        RuntimeError,
        match="EBS snapshot discovery failed",
    ):
        service.describe_snapshots()

def test_describe_security_groups_translates_client_error():
    service = EC2Service.__new__(EC2Service)
    service.ec2_client = MagicMock()

    from botocore.exceptions import ClientError

    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": "Access denied",
        }
    }

    service.ec2_client.describe_security_groups.side_effect = ClientError(
        error_response,
        "DescribeSecurityGroups",
    )

    with pytest.raises(
        RuntimeError,
        match="EC2 security-group discovery failed",
    ):
        service.describe_security_groups(["sg-001"])


def test_describe_volumes_translates_client_error():
    service = EC2Service.__new__(EC2Service)
    service.ec2_client = MagicMock()

    from botocore.exceptions import ClientError

    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": "Access denied",
        }
    }

    service.ec2_client.describe_volumes.side_effect = ClientError(
        error_response,
        "DescribeVolumes",
    )

    with pytest.raises(
        RuntimeError,
        match="EBS volume discovery failed",
    ):
        service.describe_volumes(["vol-001"])

def test_describe_instances_translates_botocore_error():
    service = EC2Service.__new__(EC2Service)
    service.ec2_client = MagicMock()

    from botocore.exceptions import BotoCoreError

    service.ec2_client.get_paginator.side_effect = BotoCoreError(
        error_message="SDK failure"
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during EC2 instance discovery",
    ):
        service.describe_instances()

def test_describe_security_groups_translates_botocore_error():
    service = EC2Service.__new__(EC2Service)
    service.ec2_client = MagicMock()

    from botocore.exceptions import BotoCoreError

    service.ec2_client.describe_security_groups.side_effect = BotoCoreError(
        error_message="SDK failure"
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during EC2 security-group discovery",
    ):
        service.describe_security_groups(["sg-001"])


def test_describe_volumes_translates_botocore_error():
    service = EC2Service.__new__(EC2Service)
    service.ec2_client = MagicMock()

    from botocore.exceptions import BotoCoreError

    service.ec2_client.describe_volumes.side_effect = BotoCoreError(
        error_message="SDK failure"
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during EBS volume discovery",
    ):
        service.describe_volumes(["vol-001"])


def test_describe_snapshots_translates_botocore_error():
    service = EC2Service.__new__(EC2Service)
    service.ec2_client = MagicMock()

    from botocore.exceptions import BotoCoreError

    service.ec2_client.get_paginator.side_effect = BotoCoreError(
        error_message="SDK failure"
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during EBS snapshot discovery",
    ):
        service.describe_snapshots()

def test_describe_all_security_groups_collects_all_pages():
    service = EC2Service.__new__(EC2Service)

    service.ec2_client = MagicMock()

    paginator = MagicMock()

    paginator.paginate.return_value = [
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-001",
                },
                {
                    "GroupId": "sg-002",
                },
            ]
        },
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-003",
                }
            ]
        },
    ]

    service.ec2_client.get_paginator.return_value = paginator

    groups = service.describe_all_security_groups()

    assert groups == [
        {
            "GroupId": "sg-001",
        },
        {
            "GroupId": "sg-002",
        },
        {
            "GroupId": "sg-003",
        },
    ]

    service.ec2_client.get_paginator.assert_called_once_with(
        "describe_security_groups"
    )

    paginator.paginate.assert_called_once_with()

def test_describe_all_security_groups_returns_empty_list():
    service = EC2Service.__new__(EC2Service)

    service.ec2_client = MagicMock()

    paginator = MagicMock()

    paginator.paginate.return_value = [
        {
            "SecurityGroups": [],
        }
    ]

    service.ec2_client.get_paginator.return_value = paginator

    groups = service.describe_all_security_groups()

    assert groups == []

    service.ec2_client.get_paginator.assert_called_once_with(
        "describe_security_groups"
    )

    paginator.paginate.assert_called_once_with()

def test_describe_all_security_groups_translates_client_error():
    service = EC2Service.__new__(EC2Service)

    service.ec2_client = MagicMock()

    error = ClientError(
        {
            "Error": {
                "Code": "UnauthorizedOperation",
                "Message": "You are not authorized",
            }
        },
        "DescribeSecurityGroups",
    )

    service.ec2_client.get_paginator.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="EC2 security-group discovery failed",
    ):
        service.describe_all_security_groups()

def test_describe_all_security_groups_translates_botocore_error():
    service = EC2Service.__new__(EC2Service)

    service.ec2_client = MagicMock()

    service.ec2_client.get_paginator.side_effect = (
        BotoCoreError(
            error_message="SDK failure"
        )
    )

    with pytest.raises(
        RuntimeError,
        match="AWS SDK error during EC2 security-group discovery",
    ):
        service.describe_all_security_groups()
