from unittest.mock import Mock

from scanner.aws.scanners.ec2 import EC2Scanner


def test_ec2_scanner_detects_public_snapshot():
    service = Mock()

    service.describe_instances.return_value = []
    service.describe_all_security_groups.return_value = []
    service.describe_volumes.return_value = []

    service.describe_snapshots.return_value = [
        {
            "SnapshotId": "snap-public-123",
            "VolumeId": "vol-123",
            "State": "completed",
            "Public": True,
        }
    ]

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    snapshot_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-005"
    ]

    assert len(snapshot_findings) == 1

    finding = snapshot_findings[0]

    assert finding.resource_id == "snap-public-123"
    assert finding.resource_type == "ebs_snapshot"
    assert finding.evidence["public"] is True


def test_ec2_scanner_ignores_private_snapshot():
    service = Mock()

    service.describe_instances.return_value = []
    service.describe_all_security_groups.return_value = []
    service.describe_volumes.return_value = []

    service.describe_snapshots.return_value = [
        {
            "SnapshotId": "snap-private-123",
            "VolumeId": "vol-123",
            "State": "completed",
            "Public": False,
        }
    ]

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    snapshot_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-005"
    ]

    assert snapshot_findings == []
