from unittest.mock import Mock

from scanner.aws.scanners.vpc_scanner import VPCScanner


def base_service():
    service = Mock()
    service.describe_vpcs.return_value = []
    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    return service


def test_vpc_scanner_detects_default_vpc():
    service = base_service()

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

    service.describe_flow_logs.return_value = [
        {
            "FlowLogId": "fl-123",
            "ResourceId": "vpc-12345678",
            "FlowLogStatus": "ACTIVE",
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-VPC-001"
    assert findings[0].title == "Default VPC is present"


def test_vpc_scanner_does_not_flag_non_default_vpc():
    service = base_service()

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

    service.describe_flow_logs.return_value = [
        {
            "FlowLogId": "fl-123",
            "ResourceId": "vpc-87654321",
            "FlowLogStatus": "ACTIVE",
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_vpc_scanner_detects_orphaned_internet_gateway():
    service = base_service()

    service.describe_vpcs.return_value = []

    service.describe_internet_gateways.return_value = [
        {
            "InternetGatewayId": "igw-12345678",
            "State": "available",
            "Attachments": [],
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-VPC-002"


def test_vpc_scanner_detects_default_security_group_with_rules():
    service = base_service()

    service.describe_default_security_groups.return_value = [
        {
            "GroupId": "sg-12345678",
            "GroupName": "default",
            "VpcId": "vpc-12345678",
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
            "IpPermissionsEgress": [],
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-VPC-003"


def test_vpc_scanner_does_not_flag_empty_default_security_group():
    service = base_service()

    service.describe_default_security_groups.return_value = [
        {
            "GroupId": "sg-12345678",
            "GroupName": "default",
            "VpcId": "vpc-12345678",
            "IpPermissions": [],
            "IpPermissionsEgress": [],
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_vpc_scanner_detects_missing_flow_logs():
    service = base_service()

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-12345678",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": False,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-12345678",
            "BlockPublicAccessStates": {
                "InternetGatewayBlockMode": "off",
            },
        }
    ]

    service.describe_flow_logs.return_value = []

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1
    assert findings[0].rule_id == "CS-AWS-VPC-004"


def test_vpc_scanner_does_not_flag_vpc_with_active_flow_logs():
    service = base_service()

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-12345678",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": False,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-12345678",
            "BlockPublicAccessStates": {
                "InternetGatewayBlockMode": "off",
            },
        }
    ]

    service.describe_flow_logs.return_value = [
        {
            "FlowLogId": "fl-123",
            "ResourceId": "vpc-12345678",
            "FlowLogStatus": "ACTIVE",
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_vpc_scanner_detects_combined_findings():
    service = base_service()

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

    service.describe_default_security_groups.return_value = [
        {
            "GroupId": "sg-12345678",
            "GroupName": "default",
            "VpcId": "vpc-12345678",
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
            "IpPermissionsEgress": [],
        }
    ]

    service.describe_flow_logs.return_value = []

    scanner = VPCScanner(service)

    findings = scanner.scan()

    rule_ids = {finding.rule_id for finding in findings}

    assert rule_ids == {
        "CS-AWS-VPC-001",
        "CS-AWS-VPC-003",
        "CS-AWS-VPC-004",
    }
