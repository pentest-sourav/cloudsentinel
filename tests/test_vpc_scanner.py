from unittest.mock import Mock

from scanner.aws.scanners.vpc_scanner import VPCScanner


def base_service():
    service = Mock()

    # Keep legacy VPC scanner fixtures isolated from newer controls.
    service.describe_subnets.return_value = []
    service.describe_client_vpn_endpoints.return_value = []
    service.describe_vpn_connections.return_value = []
    service.describe_spot_fleet_requests.return_value = []
    service.describe_network_interfaces.return_value = []

    # VPC-011..015 require interface endpoint discovery.
    # Legacy tests should not produce endpoint findings unless
    # they explicitly configure endpoint fixtures.
    service.describe_vpc_endpoints.return_value = []

    # VPC-009/010 require NACL association/entry context.
    # Default fixture should remain neutral for legacy tests.
    service.describe_network_acls.return_value = []
    service.ec2_client.meta.region_name = "us-east-1"
    service.describe_vpcs.return_value = []
    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_network_acls.return_value = []
    service.describe_vpc_block_public_access_options.return_value = {
        "AwsAccountId": "123456789012",
        "AwsRegion": "us-east-1",
        "State": "update-complete",
        "InternetGatewayBlockMode": "block-bidirectional",
        "ManagedBy": "account",
        "ExclusionsAllowed": "allowed",
    }
    # Keep all newer VPC endpoint controls compliant in legacy
    # scanner fixtures unless a test explicitly overrides them.
    service.describe_vpc_endpoints.return_value = [
        {
            "VpcId": "vpc-12345678",
            "ServiceName": "com.amazonaws.us-east-1.ec2",
        },
        {
            "VpcId": "vpc-12345678",
            "ServiceName": "com.amazonaws.us-east-1.ecr.api",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-12345678",
            "ServiceName": "com.amazonaws.us-east-1.ecr.dkr",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-12345678",
            "ServiceName": "com.amazonaws.us-east-1.ssm",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-12345678",
            "ServiceName": "com.amazonaws.us-east-1.ssm-contacts",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-12345678",
            "ServiceName": "com.amazonaws.us-east-1.ssm-incidents",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-87654321",
            "ServiceName": "com.amazonaws.us-east-1.ec2",
        },
        {
            "VpcId": "vpc-87654321",
            "ServiceName": "com.amazonaws.us-east-1.ecr.api",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-87654321",
            "ServiceName": "com.amazonaws.us-east-1.ecr.dkr",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-87654321",
            "ServiceName": "com.amazonaws.us-east-1.ssm",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-87654321",
            "ServiceName": "com.amazonaws.us-east-1.ssm-contacts",
            "VpcEndpointType": "Interface",
        },
        {
            "VpcId": "vpc-87654321",
            "ServiceName": "com.amazonaws.us-east-1.ssm-incidents",
            "VpcEndpointType": "Interface",
        },
    ]
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


def test_vpc_scanner_detects_unrestricted_network_acl():
    service = base_service()

    service.describe_network_acls.return_value = [
        {
            "NetworkAclId": "acl-12345678",
            "VpcId": "vpc-12345678",
            "IsDefault": False,
            "Entries": [
                {
                    "RuleNumber": 100,
                    "Egress": False,
                    "RuleAction": "allow",
                    "Protocol": "-1",
                    "CidrBlock": "0.0.0.0/0",
                }
            ],
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    rule_ids = {finding.rule_id for finding in findings}

    assert rule_ids == {
        "CS-AWS-VPC-009",
        "CS-AWS-VPC-010",
        "CS-AWS-VPC-005",
    }


def test_vpc_scanner_does_not_flag_default_network_acl():
    service = base_service()

    service.describe_network_acls.return_value = [
        {
            "NetworkAclId": "acl-default",
            "VpcId": "vpc-12345678",
            "IsDefault": True,
            "Entries": [
                {
                    "RuleNumber": 100,
                    "Egress": False,
                    "RuleAction": "allow",
                    "Protocol": "-1",
                    "CidrBlock": "0.0.0.0/0",
                }
            ],
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert {
        finding.rule_id
        for finding in findings
    } == {
        "CS-AWS-VPC-010",
    }


def test_vpc_scanner_detects_missing_ec2_endpoint():
    from unittest.mock import MagicMock

    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-missing",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": False,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-123",
        }
    ]

    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_network_acls.return_value = []
    service.describe_vpc_endpoints.return_value = []

    scanner = VPCScanner(service)

    findings = scanner.scan()

    endpoint_findings = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-VPC-006"
    ]

    assert len(endpoint_findings) == 1
    assert endpoint_findings[0].resource_id == "vpc-missing"


def test_vpc_scanner_accepts_standard_ec2_endpoint():
    from unittest.mock import MagicMock

    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-covered",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": False,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-123",
        }
    ]

    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_network_acls.return_value = []
    service.describe_vpc_endpoints.return_value = [
        {
            "VpcEndpointId": "vpce-123",
            "VpcId": "vpc-covered",
            "ServiceName": "com.amazonaws.us-east-1.ec2",
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert not [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-VPC-006"
    ]


def test_vpc_scanner_accepts_fips_ec2_endpoint():
    from unittest.mock import MagicMock

    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-fips",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": False,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-123",
        }
    ]

    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_network_acls.return_value = []
    service.describe_vpc_endpoints.return_value = [
        {
            "VpcEndpointId": "vpce-fips",
            "VpcId": "vpc-fips",
            "ServiceName": "com.amazonaws.us-east-1.ec2-fips",
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert not [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-VPC-006"
    ]


def test_vpc_scanner_does_not_treat_other_service_endpoint_as_ec2():
    from unittest.mock import MagicMock

    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-wrong-service",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": False,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-123",
        }
    ]

    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_network_acls.return_value = []
    service.describe_vpc_endpoints.return_value = [
        {
            "VpcEndpointId": "vpce-s3",
            "VpcId": "vpc-wrong-service",
            "ServiceName": "com.amazonaws.us-east-1.s3",
        }
    ]

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-VPC-006"
    ]
from unittest.mock import MagicMock

from scanner.aws.collectors.vpc import VPCDataCollector


def _collector():
    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = [
        {"VpcId": "vpc-1"},
        {"VpcId": "vpc-2"},
        {"VpcId": "vpc-3"},
    ]

    return service, VPCDataCollector(service)


def test_collect_ec2_endpoint_coverage_normalizes_standard_endpoint():
    service, collector = _collector()

    service.describe_vpc_endpoints.return_value = [
        {
            "VpcId": "vpc-1",
            "ServiceName": "com.amazonaws.us-east-1.ec2",
        }
    ]

    assert collector.collect_ec2_endpoint_coverage() == [
        {
            "vpc_id": "vpc-1",
            "region": "us-east-1",
            "ec2_endpoint_enabled": True,
        },
        {
            "vpc_id": "vpc-2",
            "region": "us-east-1",
            "ec2_endpoint_enabled": False,
        },
        {
            "vpc_id": "vpc-3",
            "region": "us-east-1",
            "ec2_endpoint_enabled": False,
        },
    ]


def test_collect_ec2_endpoint_coverage_accepts_fips_endpoint():
    service, collector = _collector()

    service.describe_vpc_endpoints.return_value = [
        {
            "VpcId": "vpc-2",
            "ServiceName": "com.amazonaws.us-east-1.ec2-fips",
        }
    ]

    records = collector.collect_ec2_endpoint_coverage()

    assert records[1]["ec2_endpoint_enabled"] is True


def test_collect_ec2_endpoint_coverage_ignores_other_services():
    service, collector = _collector()

    service.describe_vpc_endpoints.return_value = [
        {
            "VpcId": "vpc-1",
            "ServiceName": "com.amazonaws.us-east-1.s3",
        }
    ]

    records = collector.collect_ec2_endpoint_coverage()

    assert all(
        record["ec2_endpoint_enabled"] is False
        for record in records
    )


def test_vpc_scanner_detects_unprotected_vpc_bpa():
    from unittest.mock import MagicMock

    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = []
    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_network_acls.return_value = []
    service.describe_vpc_endpoints.return_value = []
    service.describe_vpc_block_public_access_options.return_value = {
        "AwsAccountId": "123456789012",
        "AwsRegion": "us-east-1",
        "State": "update-complete",
        "InternetGatewayBlockMode": "off",
        "ManagedBy": "account",
        "ExclusionsAllowed": "allowed",
    }

    scanner = VPCScanner(service)

    findings = scanner.scan()

    endpoint = [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-VPC-007"
    ]

    assert len(endpoint) == 1
    assert endpoint[0].resource_id == "vpc-bpa:us-east-1"
    assert endpoint[0].evidence[
        "internet_gateway_block_mode"
    ] == "off"


def test_vpc_scanner_accepts_bidirectional_vpc_bpa():
    from unittest.mock import MagicMock

    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = []
    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_network_acls.return_value = []
    service.describe_vpc_endpoints.return_value = []
    service.describe_vpc_block_public_access_options.return_value = {
        "AwsAccountId": "123456789012",
        "AwsRegion": "us-east-1",
        "State": "update-complete",
        "InternetGatewayBlockMode": "block-bidirectional",
        "ManagedBy": "account",
        "ExclusionsAllowed": "allowed",
    }

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert not [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-VPC-007"
    ]


def test_vpc_scanner_accepts_ingress_only_vpc_bpa():
    from unittest.mock import MagicMock

    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = []
    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_network_acls.return_value = []
    service.describe_vpc_endpoints.return_value = []
    service.describe_vpc_block_public_access_options.return_value = {
        "AwsAccountId": "123456789012",
        "AwsRegion": "us-east-1",
        "State": "update-complete",
        "InternetGatewayBlockMode": "block-ingress",
        "ManagedBy": "account",
        "ExclusionsAllowed": "allowed",
    }

    scanner = VPCScanner(service)

    findings = scanner.scan()

    assert not [
        finding
        for finding in findings
        if finding.rule_id == "CS-AWS-VPC-007"
    ]


def test_vpc_scanner_detects_additional_vpc_controls():
    from unittest.mock import MagicMock

    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"

    service.describe_vpcs.return_value = [
        {"VpcId": "vpc-1"}
    ]

    service.describe_internet_gateways.return_value = []
    service.describe_default_security_groups.return_value = []
    service.describe_flow_logs.return_value = []
    service.describe_vpc_endpoints.return_value = [
        {
            "VpcId": "vpc-1",
            "ServiceName": "com.amazonaws.us-east-1.ecr.api",
            "VpcEndpointType": "Interface",
        }
    ]

    service.describe_vpc_block_public_access_options.return_value = {
        "AwsRegion": "us-east-1",
        "State": "update-complete",
        "InternetGatewayBlockMode": "block-bidirectional",
        "ManagedBy": "account",
        "ExclusionsAllowed": "allowed",
    }

    service.describe_network_acls.return_value = [
        {
            "NetworkAclId": "acl-unused",
            "VpcId": "vpc-1",
            "IsDefault": False,
            "Associations": [],
            "Entries": [],
        },
        {
            "NetworkAclId": "acl-admin",
            "VpcId": "vpc-1",
            "IsDefault": False,
            "Associations": [
                {"NetworkAclAssociationId": "assoc-1"}
            ],
            "Entries": [
                {
                    "RuleNumber": 100,
                    "Egress": False,
                    "RuleAction": "allow",
                    "Protocol": "6",
                    "CidrBlock": "0.0.0.0/0",
                    "PortRange": {
                        "From": 22,
                        "To": 22,
                    },
                }
            ],
        },
    ]

    service.describe_subnets.return_value = [
        {
            "SubnetId": "subnet-public",
            "VpcId": "vpc-1",
            "MapPublicIpOnLaunch": True,
        }
    ]

    scanner = VPCScanner(service)
    findings = scanner.scan()

    rule_ids = {
        finding.rule_id
        for finding in findings
    }

    assert "CS-AWS-VPC-008" in rule_ids
    assert "CS-AWS-VPC-009" in rule_ids
    assert "CS-AWS-VPC-010" in rule_ids
    assert "CS-AWS-VPC-011" not in rule_ids
    assert "CS-AWS-VPC-012" in rule_ids
    assert "CS-AWS-VPC-013" in rule_ids
    assert "CS-AWS-VPC-014" in rule_ids
    assert "CS-AWS-VPC-015" in rule_ids
