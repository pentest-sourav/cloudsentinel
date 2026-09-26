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
