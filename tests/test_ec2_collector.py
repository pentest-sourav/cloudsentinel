from unittest.mock import Mock
from unittest.mock import MagicMock

from scanner.aws.collectors.ec2 import EC2DataCollector


def test_collect_instances_normalizes_instance_data():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "State": {"Name": "running"},
            "SecurityGroups": [
                {"GroupId": "sg-001"},
                {"GroupId": "sg-002"},
            ],
            "PublicIpAddress": "203.0.113.10",
            "PrivateIpAddress": "10.0.1.10",
        }
    ]

    collector = EC2DataCollector(service)

    instances = collector.collect_instances()

    assert instances == [
        {
            "instance_id": "i-001",
            "instance_state": "running",
            "security_group_ids": [
                "sg-001",
                "sg-002",
            ],
            "public_ip": "203.0.113.10",
            "metadata_http_tokens": None,
            "private_ip": "10.0.1.10",
        }
    ]

    service.describe_instances.assert_called_once()


def test_collect_instances_handles_missing_optional_fields():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-002",
            "State": {},
        }
    ]

    collector = EC2DataCollector(service)

    instances = collector.collect_instances()

    assert instances == [
        {
            "instance_id": "i-002",
            "instance_state": None,
            "security_group_ids": [],
            "public_ip": None,
            "private_ip": None,
            "metadata_http_tokens": None,
        }
    ]


def test_collect_instances_handles_missing_security_group_id():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-003",
            "State": {"Name": "stopped"},
            "SecurityGroups": [
                {"GroupId": "sg-003"},
                {},
            ],
        }
    ]

    collector = EC2DataCollector(service)

    instances = collector.collect_instances()

    assert instances[0]["security_group_ids"] == [
        "sg-003"
    ]


def test_collect_instances_returns_empty_list():
    service = MagicMock()

    service.describe_instances.return_value = []

    collector = EC2DataCollector(service)

    instances = collector.collect_instances()

    assert instances == []


def test_collect_security_groups_from_instances():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "SecurityGroups": [
                {"GroupId": "sg-002"},
                {"GroupId": "sg-001"},
            ],
        },
        {
            "InstanceId": "i-002",
            "SecurityGroups": [
                {"GroupId": "sg-001"},
            ],
        },
    ]

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-001",
            "GroupName": "web",
        },
        {
            "GroupId": "sg-002",
            "GroupName": "ssh",
        },
    ]

    collector = EC2DataCollector(service)

    groups = collector.collect_security_groups()

    assert groups == [
        {
            "GroupId": "sg-001",
            "GroupName": "web",
        },
        {
            "GroupId": "sg-002",
            "GroupName": "ssh",
        },
    ]

    service.describe_security_groups.assert_called_once_with(
        ["sg-001", "sg-002"]
    )


def test_collect_security_groups_handles_duplicate_group_ids():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "SecurityGroups": [
                {"GroupId": "sg-001"},
            ],
        },
        {
            "InstanceId": "i-002",
            "SecurityGroups": [
                {"GroupId": "sg-001"},
            ],
        },
    ]

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-001",
        }
    ]

    collector = EC2DataCollector(service)

    groups = collector.collect_security_groups()

    assert groups == [
        {
            "GroupId": "sg-001",
        }
    ]

    service.describe_security_groups.assert_called_once_with(
        ["sg-001"]
    )


def test_collect_security_groups_handles_missing_group_id():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "SecurityGroups": [
                {},
                {"GroupId": "sg-001"},
            ],
        }
    ]

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-001",
        }
    ]

    collector = EC2DataCollector(service)

    groups = collector.collect_security_groups()

    assert groups == [
        {
            "GroupId": "sg-001",
        }
    ]

    service.describe_security_groups.assert_called_once_with(
        ["sg-001"]
    )


def test_collect_security_groups_returns_empty_when_no_groups():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "SecurityGroups": [],
        }
    ]

    service.describe_security_groups.return_value = []

    collector = EC2DataCollector(service)

    groups = collector.collect_security_groups()

    assert groups == []

    service.describe_security_groups.assert_called_once_with([])

def test_collect_instances_includes_metadata_http_tokens():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PublicIpAddress": "203.0.113.10",
            "PrivateIpAddress": "10.0.1.10",
            "MetadataOptions": {
                "HttpTokens": "optional",
            },
        }
    ]

    collector = EC2DataCollector(service)

    instances = collector.collect_instances()

    assert len(instances) == 1
    assert instances[0]["instance_id"] == "i-001"
    assert instances[0]["metadata_http_tokens"] == "optional"

def test_collect_ebs_volumes_for_instances():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "State": {"Name": "running"},
            "SecurityGroups": [],
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "VolumeId": "vol-001",
                    },
                },
                {
                    "DeviceName": "/dev/sdb",
                    "Ebs": {
                        "VolumeId": "vol-002",
                    },
                },
            ],
        }
    ]

    service.describe_volumes.return_value = [
        {
            "VolumeId": "vol-001",
            "Encrypted": False,
        },
        {
            "VolumeId": "vol-002",
            "Encrypted": True,
        },
    ]

    collector = EC2DataCollector(service)

    volumes = collector.collect_ebs_volumes()

    assert volumes == [
        {
            "instance_id": "i-001",
            "volume_id": "vol-001",
            "encrypted": False,
        },
        {
            "instance_id": "i-001",
            "volume_id": "vol-002",
            "encrypted": True,
        },
    ]
