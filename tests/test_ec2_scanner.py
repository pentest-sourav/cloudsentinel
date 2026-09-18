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

    service.describe_all_security_groups.return_value = [
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

    service.describe_volumes.return_value = []
    service.describe_snapshots.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-EC2-001"
    assert findings[0].severity.value == "high"
    assert findings[0].resource_id == "sg-001"


def test_ec2_scanner_ignores_private_security_group_rules():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-002",
            "SecurityGroups": [
                {"GroupId": "sg-private"},
            ],
        }
    ]

    service.describe_all_security_groups.return_value = [
        {
            "GroupId": "sg-private",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "10.0.0.0/16",
                        }
                    ],
                }
            ],
        }
    ]

    service.describe_volumes.return_value = []
    service.describe_snapshots.return_value = []

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

    service.describe_all_security_groups.return_value = [
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

    service.describe_volumes.return_value = []
    service.describe_snapshots.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    assert len(findings) == 2

    finding_rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert finding_rule_ids == {
        "CS-AWS-EC2-001",
    }

    finding_resource_ids = {
        finding.resource_id
        for finding in findings
    }

    assert finding_resource_ids == {
        "sg-001",
        "sg-002",
    }


def test_ec2_scanner_ignores_unrelated_security_group_rules():
    service = MagicMock()

    service.describe_instances.return_value = [
        {
            "InstanceId": "i-004",
            "SecurityGroups": [
                {"GroupId": "sg-mixed"},
            ],
        }
    ]

    service.describe_all_security_groups.return_value = [
        {
            "GroupId": "sg-mixed",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [
                        {
                            "CidrIp": "0.0.0.0/0",
                        }
                    ],
                },
            ],
        }
    ]

    service.describe_volumes.return_value = []
    service.describe_snapshots.return_value = []

    scanner = EC2Scanner(service)

    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].resource_id == "sg-mixed"
    assert findings[0].rule_id == "CS-AWS-EC2-001"
