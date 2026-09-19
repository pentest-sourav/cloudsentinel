from unittest.mock import Mock

from scanner.aws.scanners.vpc_scanner import VPCScanner


def test_vpc_scanner_detects_default_vpc():
    service = Mock()

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-12345678",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": True,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-12345678",
            "BlockPublicAccessStates": {
                "InternetGatewayBlockMode": "off",
            },
        }
    ]

    service.describe_internet_gateways.return_value = []

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-VPC-001"
    assert finding.severity.value == "medium"
    assert finding.resource_type == "vpc"
    assert finding.resource_id == "vpc-12345678"


def test_vpc_scanner_does_not_flag_non_default_vpc():
    service = Mock()

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-87654321",
            "CidrBlock": "10.1.0.0/16",
            "State": "available",
            "IsDefault": False,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-87654321",
            "BlockPublicAccessStates": {
                "InternetGatewayBlockMode": "off",
            },
        }
    ]

    service.describe_internet_gateways.return_value = []

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_vpc_scanner_handles_empty_account():
    service = Mock()
    service.describe_vpcs.return_value = []
    service.describe_internet_gateways.return_value = []

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_vpc_scanner_detects_orphaned_internet_gateway():
    service = Mock()

    service.describe_vpcs.return_value = []

    service.describe_internet_gateways.return_value = [
        {
            "InternetGatewayId": "igw-12345678",
            "Attachments": [],
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-VPC-002"
    assert finding.severity.value == "low"
    assert finding.resource_type == "internet_gateway"
    assert finding.resource_id == "igw-12345678"


def test_vpc_scanner_does_not_flag_attached_internet_gateway():
    service = Mock()

    service.describe_vpcs.return_value = []

    service.describe_internet_gateways.return_value = [
        {
            "InternetGatewayId": "igw-87654321",
            "Attachments": [
                {
                    "State": "available",
                    "VpcId": "vpc-12345678",
                }
            ],
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert findings == []
