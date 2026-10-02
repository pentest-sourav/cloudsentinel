from unittest.mock import Mock

from scanner.aws.scanners.efs import EFSScanner


def test_efs_scanner_executes_registered_rules():
    service = Mock()

    service.list_file_systems.return_value = [
        {
            "FileSystemId": "fs-unencrypted",
            "Encrypted": False,
            "Backup": False,
            "BackupPolicy": {
                "Status": "DISABLED",
            },
        },
    ]

    service.list_mount_targets.return_value = [
        {
            "MountTargetId": "fsmt-public",
            "FileSystemId": "fs-unencrypted",
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

    service.list_access_points.return_value = [
        {
            "AccessPointId": "ap-insecure",
            "FileSystemId": "fs-unencrypted",
            "RootDirectory": {
                "Path": "/",
            },
            "PosixUser": {},
        },
    ]

    findings = EFSScanner(service).scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert rule_ids == {
        "CS-AWS-EFS-001",
        "CS-AWS-EFS-002",
        "CS-AWS-EFS-003",
        "CS-AWS-EFS-004",
        "CS-AWS-EFS-005",
        "CS-AWS-EFS-006",
    }
