from unittest.mock import Mock

from scanner.aws.scanners.ec2 import EC2Scanner


def test_ec2_scanner_detects_public_instance():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-public-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PublicIpAddress": "203.0.113.10",
            "PrivateIpAddress": "10.0.1.10",
        }
    ]

    service.describe_security_groups.return_value = []
    service.describe_volumes.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    public_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-002"
    ]

    assert len(public_findings) == 1

    finding = public_findings[0]

    assert finding.resource_id == "i-public-001"
    assert finding.severity.value == "medium"
    assert finding.evidence["public_ip"] == "203.0.113.10"
    assert finding.evidence["internet_exposed"] is True


def test_ec2_scanner_does_not_flag_private_instance():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-private-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PrivateIpAddress": "10.0.1.20",
        }
    ]

    service.describe_security_groups.return_value = []
    service.describe_volumes.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    public_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-002"
    ]

    assert public_findings == []


def test_ec2_scanner_handles_public_and_private_instances():
    service = Mock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-public-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PublicIpAddress": "203.0.113.10",
            "PrivateIpAddress": "10.0.1.10",
        },
        {
            "InstanceId": "i-private-001",
            "State": {
                "Name": "running",
            },
            "SecurityGroups": [],
            "PrivateIpAddress": "10.0.1.20",
        },
    ]

    service.describe_security_groups.return_value = []
    service.describe_volumes.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    public_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-EC2-002"
    ]

    assert len(public_findings) == 1
    assert public_findings[0].resource_id == "i-public-001"
