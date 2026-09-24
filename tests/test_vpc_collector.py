from unittest.mock import MagicMock

from scanner.aws.collectors.vpc import VPCDataCollector


def test_vpc_collector_normalizes_vpc():
    service = MagicMock()

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-123456789",
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
            "IsDefault": True,
            "InstanceTenancy": "default",
            "DhcpOptionsId": "dopt-123456",
            "BlockPublicAccessStates": {
                "InternetGatewayBlockMode": "off"
            },
        }
    ]

    collector = VPCDataCollector(service)

    vpcs = collector.collect_vpcs()

    assert len(vpcs) == 1

    vpc = vpcs[0]

    assert vpc["vpc_id"] == "vpc-123456789"
    assert vpc["cidr_block"] == "10.0.0.0/16"
    assert vpc["state"] == "available"
    assert vpc["is_default"] is True
    assert vpc["instance_tenancy"] == "default"
    assert vpc["dhcp_options_id"] == "dopt-123456"
    assert vpc["internet_gateway_block_mode"] == "off"


def test_vpc_collector_ignores_vpc_without_id():
    service = MagicMock()

    service.describe_vpcs.return_value = [
        {
            "CidrBlock": "10.0.0.0/16",
            "State": "available",
        }
    ]

    collector = VPCDataCollector(service)

    vpcs = collector.collect_vpcs()

    assert vpcs == []


def test_vpc_collector_handles_empty_account():
    service = MagicMock()

    service.describe_vpcs.return_value = []

    collector = VPCDataCollector(service)

    vpcs = collector.collect_vpcs()

    assert vpcs == []


def test_vpc_collector_normalizes_internet_gateway():
    service = MagicMock()

    service.describe_internet_gateways.return_value = [
        {
            "InternetGatewayId": "igw-123456789",
            "Attachments": [
                {
                    "State": "available",
                    "VpcId": "vpc-123456789",
                }
            ],
        }
    ]

    collector = VPCDataCollector(service)

    gateways = collector.collect_internet_gateways()

    assert len(gateways) == 1

    gateway = gateways[0]

    assert gateway["internet_gateway_id"] == "igw-123456789"
    assert gateway["vpc_id"] == "vpc-123456789"
    assert gateway["state"] == "available"


def test_vpc_collector_handles_multiple_internet_gateway_attachments():
    service = MagicMock()

    service.describe_internet_gateways.return_value = [
        {
            "InternetGatewayId": "igw-123456789",
            "Attachments": [
                {
                    "State": "available",
                    "VpcId": "vpc-111111111",
                },
                {
                    "State": "available",
                    "VpcId": "vpc-222222222",
                },
            ],
        }
    ]

    collector = VPCDataCollector(service)

    gateways = collector.collect_internet_gateways()

    assert len(gateways) == 2
    assert gateways[0]["vpc_id"] == "vpc-111111111"
    assert gateways[1]["vpc_id"] == "vpc-222222222"


def test_vpc_collector_ignores_internet_gateway_without_id():
    service = MagicMock()

    service.describe_internet_gateways.return_value = [
        {
            "Attachments": [
                {
                    "State": "available",
                    "VpcId": "vpc-123456789",
                }
            ]
        }
    ]

    collector = VPCDataCollector(service)

    gateways = collector.collect_internet_gateways()

    assert gateways == []


def test_vpc_collector_handles_empty_internet_gateways():
    service = MagicMock()

    service.describe_internet_gateways.return_value = []

    collector = VPCDataCollector(service)

    gateways = collector.collect_internet_gateways()

    assert gateways == []


def test_vpc_collector_normalizes_default_security_groups():
    service = MagicMock()

    service.describe_default_security_groups.return_value = [
        {
            "GroupId": "sg-default",
            "GroupName": "default",
            "VpcId": "vpc-123",
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "UserIdGroupPairs": [
                        {"GroupId": "sg-default"}
                    ],
                }
            ],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]

    collector = VPCDataCollector(service)

    groups = collector.collect_default_security_groups()

    assert groups == [
        {
            "group_id": "sg-default",
            "vpc_id": "vpc-123",
            "group_name": "default",
            "inbound_rule_count": 1,
            "outbound_rule_count": 1,
        }
    ]


def test_vpc_collector_ignores_default_security_group_without_ids():
    service = MagicMock()

    service.describe_default_security_groups.return_value = [
        {
            "GroupName": "default",
        }
    ]

    collector = VPCDataCollector(service)

    assert collector.collect_default_security_groups() == []


def test_vpc_collector_detects_active_flow_log_coverage():
    service = MagicMock()

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-123",
            "CidrBlock": "10.0.0.0/16",
        },
        {
            "VpcId": "vpc-456",
            "CidrBlock": "10.1.0.0/16",
        },
    ]

    service.describe_flow_logs.return_value = [
        {
            "FlowLogId": "fl-123",
            "ResourceId": "vpc-123",
            "FlowLogStatus": "ACTIVE",
        },
        {
            "FlowLogId": "fl-456",
            "ResourceId": "vpc-456",
            "FlowLogStatus": "FAILED",
        },
    ]

    collector = VPCDataCollector(service)

    coverage = collector.collect_flow_log_coverage()

    assert coverage == [
        {
            "vpc_id": "vpc-123",
            "flow_log_count": 1,
            "active_flow_log_count": 1,
            "flow_logging_enabled": True,
        },
        {
            "vpc_id": "vpc-456",
            "flow_log_count": 1,
            "active_flow_log_count": 0,
            "flow_logging_enabled": False,
        },
    ]


def test_vpc_collector_marks_vpc_without_flow_log_as_disabled():
    service = MagicMock()

    service.describe_vpcs.return_value = [
        {
            "VpcId": "vpc-123",
        }
    ]

    service.describe_flow_logs.return_value = []

    collector = VPCDataCollector(service)

    assert collector.collect_flow_log_coverage() == [
        {
            "vpc_id": "vpc-123",
            "flow_log_count": 0,
            "active_flow_log_count": 0,
            "flow_logging_enabled": False,
        }
    ]


def test_vpc_collector_normalizes_network_acl_entries():
    service = MagicMock()

    service.describe_network_acls.return_value = [
        {
            "NetworkAclId": "acl-123",
            "VpcId": "vpc-123",
            "IsDefault": False,
            "Entries": [
                {
                    "RuleNumber": 100,
                    "Egress": False,
                    "RuleAction": "allow",
                    "Protocol": "-1",
                    "CidrBlock": "0.0.0.0/0",
                },
                {
                    "RuleNumber": 110,
                    "Egress": True,
                    "RuleAction": "deny",
                    "Protocol": "6",
                    "Ipv6CidrBlock": "::/0",
                },
            ],
        }
    ]

    collector = VPCDataCollector(service)

    entries = collector.collect_network_acls()

    assert entries == [
        {
            "network_acl_id": "acl-123",
            "vpc_id": "vpc-123",
            "is_default": False,
            "rule_number": 100,
            "egress": False,
            "rule_action": "allow",
            "protocol": "-1",
            "cidr_block": "0.0.0.0/0",
            "ipv6_cidr_block": None,
        },
        {
            "network_acl_id": "acl-123",
            "vpc_id": "vpc-123",
            "is_default": False,
            "rule_number": 110,
            "egress": True,
            "rule_action": "deny",
            "protocol": "6",
            "cidr_block": None,
            "ipv6_cidr_block": "::/0",
        },
    ]
