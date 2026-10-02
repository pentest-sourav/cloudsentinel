from unittest.mock import Mock

from scanner.aws.collectors.efs import EFSDataCollector


def test_collect_file_systems_normalizes_security_fields():
    service = Mock()

    service.list_file_systems.return_value = [
        {
            "FileSystemId": "fs-123",
            "FileSystemArn": (
                "arn:aws:elasticfilesystem:us-east-1:"
                "123456789012:file-system/fs-123"
            ),
            "Name": "prod",
            "Encrypted": True,
            "KmsKeyId": "arn:aws:kms:example",
            "Backup": True,
            "BackupPolicy": {
                "Status": "ENABLED",
            },
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        },
    ]

    collector = EFSDataCollector(service)

    result = collector.collect_file_systems()

    assert result == [
        {
            "resource_id": "fs-123",
            "resource_type": "efs_file_system",
            "resource_arn": (
                "arn:aws:elasticfilesystem:us-east-1:"
                "123456789012:file-system/fs-123"
            ),
            "name": "prod",
            "encrypted": True,
            "kms_key_id": "arn:aws:kms:example",
            "backup": True,
            "backup_policy_status": "ENABLED",
            "life_cycle_state": None,
            "performance_mode": None,
            "throughput_mode": None,
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                },
            ],
        },
    ]


def test_collect_access_points_normalizes_root_and_posix_user():
    service = Mock()

    service.list_access_points.return_value = [
        {
            "AccessPointId": "ap-123",
            "AccessPointArn": "arn:aws:efs:example",
            "FileSystemId": "fs-123",
            "RootDirectory": {
                "Path": "/application",
                "CreationInfo": {
                    "OwnerUid": 1000,
                    "OwnerGid": 1000,
                },
            },
            "PosixUser": {
                "Uid": 1000,
                "Gid": 1000,
                "SecondaryGids": [1001],
            },
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "Production",
                },
                {
                    "Key": "aws:createdBy",
                    "Value": "system",
                },
            ],
        },
    ]

    collector = EFSDataCollector(service)

    assert collector.collect_access_points() == [
        {
            "resource_id": "ap-123",
            "resource_type": "efs_access_point",
            "resource_arn": "arn:aws:efs:example",
            "file_system_id": "fs-123",
            "root_directory_path": "/application",
            "root_directory_creation_info": {
                "OwnerUid": 1000,
                "OwnerGid": 1000,
            },
            "posix_uid": 1000,
            "posix_gid": 1000,
            "secondary_gids": [1001],
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "Production",
                },
            ],
            "has_non_system_tags": True,
        },
    ]


def test_collect_access_points_detects_missing_non_system_tags():
    service = Mock()

    service.list_access_points.return_value = [
        {
            "AccessPointId": "ap-456",
            "Tags": [
                {
                    "Key": "aws:createdBy",
                    "Value": "system",
                },
            ],
        },
    ]

    collector = EFSDataCollector(service)

    result = collector.collect_access_points()

    assert result == [
        {
            "resource_id": "ap-456",
            "resource_type": "efs_access_point",
            "resource_arn": None,
            "file_system_id": None,
            "root_directory_path": None,
            "root_directory_creation_info": None,
            "posix_uid": None,
            "posix_gid": None,
            "secondary_gids": None,
            "tags": [],
            "has_non_system_tags": False,
        },
    ]


def test_collector_caches_file_systems():
    service = Mock()

    service.list_file_systems.return_value = [
        {
            "FileSystemId": "fs-123",
            "Encrypted": True,
        },
    ]

    collector = EFSDataCollector(service)

    collector.collect_file_systems()
    collector.collect_file_systems()

    service.list_file_systems.assert_called_once()


def test_collect_mount_targets_normalizes_public_subnet_state():
    service = Mock()

    service.list_file_systems.return_value = [
        {
            "FileSystemId": "fs-123",
        },
    ]

    service.list_mount_targets.return_value = [
        {
            "MountTargetId": "fsmt-123",
            "FileSystemId": "fs-123",
            "SubnetId": "subnet-public",
            "VpcId": "vpc-123",
        },
    ]

    service.list_subnets.return_value = [
        {
            "SubnetId": "subnet-public",
            "MapPublicIpOnLaunch": True,
        },
    ]

    collector = EFSDataCollector(service)

    assert collector.collect_mount_targets() == [
        {
            "resource_id": "fsmt-123",
            "resource_type": "efs_mount_target",
            "file_system_id": "fs-123",
            "subnet_id": "subnet-public",
            "vpc_id": "vpc-123",
            "map_public_ip_on_launch": True,
        },
    ]


def test_collect_mount_targets_caches_mount_targets_and_subnets():
    service = Mock()

    service.list_file_systems.return_value = [
        {
            "FileSystemId": "fs-123",
        },
    ]

    service.list_mount_targets.return_value = []

    service.list_subnets.return_value = []

    collector = EFSDataCollector(service)

    collector.collect_mount_targets()
    collector.collect_mount_targets()

    service.list_file_systems.assert_called_once()
    service.list_mount_targets.assert_called_once_with(
        "fs-123"
    )
    service.list_subnets.assert_called_once()
