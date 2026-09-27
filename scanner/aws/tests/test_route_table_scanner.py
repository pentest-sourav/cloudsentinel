from unittest.mock import Mock

from scanner.aws.scanners.route_table_scanner import RouteTableScanner


def test_route_table_scanner_returns_findings():
    service = Mock()

    service.describe_route_tables.return_value = [
        {
            "RouteTableId": "rtb-123",
            "VpcId": "vpc-123",
            "Routes": [
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-123",
                    "State": "active",
                },
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "GatewayId": "local",
                    "State": "active",
                },
            ],
            "Associations": [],
            "PropagatingVgws": [],
            "Tags": [],
        }
    ]

    scanner = RouteTableScanner(service)
    findings = scanner.scan()

    rule_ids = {finding.rule_id for finding in findings}

    assert "CS-AWS-RT-001" in rule_ids
    assert "CS-AWS-RT-002" in rule_ids


def test_route_table_scanner_returns_no_findings_when_secure():
    service = Mock()

    service.describe_route_tables.return_value = [
        {
            "RouteTableId": "rtb-123",
            "VpcId": "vpc-123",
            "Routes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "GatewayId": "local",
                    "State": "active",
                }
            ],
            "Associations": [],
            "PropagatingVgws": [],
            "Tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        }
    ]

    scanner = RouteTableScanner(service)

    assert scanner.scan() == []
