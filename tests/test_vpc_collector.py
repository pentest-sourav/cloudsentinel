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
