from unittest.mock import MagicMock

from scanner.aws.scanners.ec2 import EC2Scanner


def test_ec2_scanner_returns_security_group_findings():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-001",
            "SecurityGroups": [
                {"GroupId": "sg-001"},
            ],
        }
    ]

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-001",
            "GroupName": "public-ssh",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                }
            ],
        }
    ]

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-EC2-001"
    assert finding.title == "SSH Port Exposed to the Internet"
    assert finding.severity.value == "high"
    assert finding.provider == "aws"
    assert finding.resource_type == "ec2_security_group"
    assert finding.resource_id == "sg-001"

    assert finding.evidence["source"] == "0.0.0.0/0"
    assert finding.evidence["from_port"] == 22
    assert finding.evidence["to_port"] == 22


def test_ec2_scanner_returns_no_findings_for_private_ssh():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-002",
            "SecurityGroups": [
                {"GroupId": "sg-private"},
            ],
        }
    ]

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-private",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "10.0.0.0/8",
                        }
                    ],
                }
            ],
        }
    ]

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    assert findings == []


def test_ec2_scanner_handles_multiple_security_groups():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-003",
            "SecurityGroups": [
                {"GroupId": "sg-001"},
                {"GroupId": "sg-002"},
            ],
        }
    ]

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-001",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                }
            ],
        },
        {
            "GroupId": "sg-002",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "Ipv6Ranges": [
                        {
                            "CidrIpv6": "::/0",
                        }
                    ],
                }
            ],
        },
    ]

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    assert len(findings) == 2

    assert findings[0].rule_id == "CS-AWS-EC2-001"
    assert findings[1].rule_id == "CS-AWS-EC2-001"

    assert {
        finding.resource_id
        for finding in findings
    } == {
        "sg-001",
        "sg-002",
    }
