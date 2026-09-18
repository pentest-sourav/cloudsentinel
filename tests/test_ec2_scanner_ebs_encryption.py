from unittest.mock import Mock

from scanner.aws.scanners.ec2 import EC2Scanner


def test_ec2_scanner_detects_unencrypted_ebs_volume():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-ebs-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "VolumeId": "vol-unencrypted-001",
                    },
                }
            ],
        }
    ]

    service.describe_all_security_groups.return_value = []
    service.describe_snapshots.return_value = []

    service.describe_volumes.return_value = [
        {
            "VolumeId": "vol-unencrypted-001",
            "Encrypted": False,
        }
    ]

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    ebs_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-004"
    ]

    assert len(ebs_findings) == 1

    finding = ebs_findings[0]

    assert finding.resource_id == "vol-unencrypted-001"
    assert finding.severity.value == "high"
    assert finding.evidence["instance_id"] == "i-ebs-001"
    assert finding.evidence["volume_id"] == "vol-unencrypted-001"
    assert finding.evidence["encrypted"] is False


def test_ec2_scanner_does_not_flag_encrypted_ebs_volume():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-ebs-002",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "VolumeId": "vol-encrypted-001",
                    },
                }
            ],
        }
    ]

    service.describe_all_security_groups.return_value = []
    service.describe_snapshots.return_value = []

    service.describe_volumes.return_value = [
        {
            "VolumeId": "vol-encrypted-001",
            "Encrypted": True,
        }
    ]

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    ebs_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-004"
    ]

    assert ebs_findings == []


def test_ec2_scanner_handles_mixed_ebs_encryption():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-ebs-003",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "VolumeId": "vol-unencrypted-002",
                    },
                },
                {
                    "DeviceName": "/dev/sdb",
                    "Ebs": {
                        "VolumeId": "vol-encrypted-002",
                    },
                },
            ],
        }
    ]

    service.describe_all_security_groups.return_value = []
    service.describe_snapshots.return_value = []

    service.describe_volumes.return_value = [
        {
            "VolumeId": "vol-unencrypted-002",
            "Encrypted": False,
        },
        {
            "VolumeId": "vol-encrypted-002",
            "Encrypted": True,
        },
    ]

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    ebs_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-004"
    ]

    assert len(ebs_findings) == 1
    assert ebs_findings[0].resource_id == "vol-unencrypted-002"
