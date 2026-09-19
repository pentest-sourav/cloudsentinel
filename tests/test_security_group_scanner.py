from unittest.mock import Mock

from scanner.aws.scanners.security_group_scanner import (
    SecurityGroupScanner,
)


def test_security_group_scanner_detects_unrestricted_inbound():
    service = Mock()

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-test",
            "GroupName": "web-sg",
            "Description": "Test security group",
            "VpcId": "vpc-test",
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
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
            "IpPermissionsEgress": [],
        }
    ]

    scanner = SecurityGroupScanner(service)
    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-SG-001"
    assert finding.severity.value == "high"
    assert finding.resource_id == "sg-test"
    assert finding.evidence["cidr"] == "0.0.0.0/0"


def test_security_group_scanner_returns_no_finding_for_restricted_inbound():
    service = Mock()

    service.describe_security_groups.return_value = [
        {
            "GroupId": "sg-test",
            "GroupName": "internal-sg",
            "Description": "Internal security group",
            "VpcId": "vpc-test",
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
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
            "IpPermissionsEgress": [],
        }
    ]

    scanner = SecurityGroupScanner(service)
    findings = scanner.scan()

    assert findings == []
