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
        }
    ]

    scanner = RouteTableScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-RT-001"
    assert finding.resource_id == "rtb-123"
    assert finding.severity.value == "low"
    assert finding.evidence["gateway_id"] == "igw-123"


def test_route_table_scanner_returns_no_findings_when_no_default_route():
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
        }
    ]

    scanner = RouteTableScanner(service)

    findings = scanner.scan()

    assert findings == []
