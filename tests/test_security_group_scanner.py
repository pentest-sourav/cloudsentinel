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
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
            "IpPermissionsEgress": [],
        }
    ]

    service.describe_network_interfaces.return_value = []

    scanner = SecurityGroupScanner(service)
    findings = scanner.scan()

    rule_ids = {finding.rule_id for finding in findings}

    assert "CS-AWS-SG-001" in rule_ids
    assert "CS-AWS-SG-002" in rule_ids
    assert "CS-AWS-SG-003" in rule_ids
    assert "CS-AWS-SG-004" in rule_ids
    assert "CS-AWS-SG-005" in rule_ids


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
                    "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
            "IpPermissionsEgress": [],
        }
    ]

    service.describe_network_interfaces.return_value = [
        {
            "NetworkInterfaceId": "eni-test",
            "Groups": [
                {
                    "GroupId": "sg-test",
                    "GroupName": "internal-sg",
                }
            ],
        }
    ]

    scanner = SecurityGroupScanner(service)
    findings = scanner.scan()

    assert findings == []
