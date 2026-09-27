from unittest.mock import MagicMock

from engine.rules.aws.vpc.block_public_access import (
    build_vpc_block_public_access_finding,
    check_vpc_block_public_access,
)
from scanner.aws.collectors.vpc import VPCDataCollector
from scanner.aws.services.vpc import VPCService


def test_check_vpc_block_public_access_flags_off_mode():
    result = check_vpc_block_public_access(
        region="us-east-1",
        internet_gateway_block_mode="off",
        state="update-complete",
        managed_by="account",
        exclusions_allowed="allowed",
    )

    assert result is not None
    assert result.region == "us-east-1"
    assert result.internet_gateway_block_mode == "off"


def test_check_vpc_block_public_access_accepts_bidirectional_mode():
    result = check_vpc_block_public_access(
        region="us-east-1",
        internet_gateway_block_mode="block-bidirectional",
        state="update-complete",
        managed_by="account",
        exclusions_allowed="allowed",
    )

    assert result is None


def test_check_vpc_block_public_access_accepts_ingress_mode():
    result = check_vpc_block_public_access(
        region="us-east-1",
        internet_gateway_block_mode="block-ingress",
        state="update-complete",
        managed_by="account",
        exclusions_allowed="allowed",
    )

    assert result is None


def test_check_vpc_block_public_access_treats_missing_mode_as_failure():
    result = check_vpc_block_public_access(
        region="us-east-1",
        internet_gateway_block_mode=None,
        state=None,
        managed_by=None,
        exclusions_allowed=None,
    )

    assert result is not None


def test_build_vpc_block_public_access_finding():
    result = check_vpc_block_public_access(
        region="us-east-1",
        internet_gateway_block_mode="off",
        state="update-complete",
        managed_by="account",
        exclusions_allowed="allowed",
    )

    assert result is not None

    finding = build_vpc_block_public_access_finding(result)

    assert finding.rule_id == "CS-AWS-VPC-007"
    assert finding.resource_type == "vpc_block_public_access_options"
    assert finding.resource_id == "vpc-bpa:us-east-1"
    assert finding.severity.value == "medium"
    assert finding.evidence["internet_gateway_block_mode"] == "off"
    assert finding.compliance == [
        "AWS Security Hub EC2.172"
    ]


def test_vpc_collector_normalizes_bpa_options():
    service = MagicMock()
    service.ec2_client.meta.region_name = "us-east-1"
    service.describe_vpc_block_public_access_options.return_value = {
        "AwsAccountId": "123456789012",
        "AwsRegion": "us-east-1",
        "State": "update-complete",
        "InternetGatewayBlockMode": "block-ingress",
        "ManagedBy": "account",
        "ExclusionsAllowed": "allowed",
    }

    collector = VPCDataCollector(service)

    assert collector.collect_vpc_block_public_access_options() == {
        "region": "us-east-1",
        "internet_gateway_block_mode": "block-ingress",
        "state": "update-complete",
        "managed_by": "account",
        "exclusions_allowed": "allowed",
    }


def test_vpc_service_describes_bpa_options():
    client = MagicMock()
    client.describe_vpc_block_public_access_options.return_value = {
        "VpcBlockPublicAccessOptions": {
            "AwsAccountId": "123456789012",
            "AwsRegion": "us-east-1",
            "State": "update-complete",
            "InternetGatewayBlockMode": "block-bidirectional",
            "ManagedBy": "account",
            "ExclusionsAllowed": "allowed",
        }
    }

    service = VPCService.__new__(VPCService)
    service.session = None
    service.ec2_client = client

    assert service.describe_vpc_block_public_access_options() == {
        "AwsAccountId": "123456789012",
        "AwsRegion": "us-east-1",
        "State": "update-complete",
        "InternetGatewayBlockMode": "block-bidirectional",
        "ManagedBy": "account",
        "ExclusionsAllowed": "allowed",
    }
