from unittest.mock import Mock

from scanner.aws.scanners.ec2 import EC2Scanner


def test_ec2_scanner_detects_imdsv1_enabled():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-imdsv1-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PublicIpAddress": None,
            "PrivateIpAddress": "10.0.1.10",
            "MetadataOptions": {
                "HttpTokens": "optional",
            },
        }
    ]

    service.describe_all_security_groups.return_value = []
    service.describe_volumes.return_value = []
    service.describe_snapshots.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    imdsv1_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-003"
    ]

    assert len(imdsv1_findings) == 1

    finding = imdsv1_findings[0]

    assert finding.resource_id == "i-imdsv1-001"
    assert finding.severity.value == "high"
    assert finding.evidence["instance_id"] == "i-imdsv1-001"
    assert finding.evidence["http_tokens"] == "optional"


def test_ec2_scanner_does_not_flag_imdsv2_required():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-imdsv2-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PublicIpAddress": None,
            "PrivateIpAddress": "10.0.1.20",
            "MetadataOptions": {
                "HttpTokens": "required",
            },
        }
    ]

    service.describe_all_security_groups.return_value = []
    service.describe_volumes.return_value = []
    service.describe_snapshots.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    imdsv1_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-003"
    ]

    assert imdsv1_findings == []


def test_ec2_scanner_handles_mixed_imdsv1_and_imdsv2():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-imdsv1-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PublicIpAddress": None,
            "PrivateIpAddress": "10.0.1.10",
            "MetadataOptions": {
                "HttpTokens": "optional",
            },
        },
        {
            "InstanceId": "i-imdsv2-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PublicIpAddress": None,
            "PrivateIpAddress": "10.0.1.20",
            "MetadataOptions": {
                "HttpTokens": "required",
            },
        },
    ]

    service.describe_all_security_groups.return_value = []
    service.describe_volumes.return_value = []
    service.describe_snapshots.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    imdsv1_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-003"
    ]

    assert len(imdsv1_findings) == 1
    assert imdsv1_findings[0].resource_id == "i-imdsv1-001"
