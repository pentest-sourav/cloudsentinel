from engine.findings.model import Severity
from engine.rules.aws.route_tables.default_route import (
    build_default_route_finding,
    check_default_route,
)


def test_active_default_route_to_internet_gateway():
    result = check_default_route(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        route={
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": "igw-123",
            "State": "active",
        },
    )

    assert result is not None
    assert result.route_table_id == "rtb-123"
    assert result.vpc_id == "vpc-123"
    assert result.destination == "0.0.0.0/0"
    assert result.gateway_id == "igw-123"
    assert result.state == "active"


def test_local_route_is_ignored():
    result = check_default_route(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        route={
            "DestinationCidrBlock": "10.0.0.0/16",
            "GatewayId": "local",
            "State": "active",
        },
    )

    assert result is None


def test_default_route_to_nat_gateway_is_ignored():
    result = check_default_route(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        route={
            "DestinationCidrBlock": "0.0.0.0/0",
            "NatGatewayId": "nat-123",
            "State": "active",
        },
    )

    assert result is None


def test_blackhole_default_route_is_ignored():
    result = check_default_route(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        route={
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": "igw-123",
            "State": "blackhole",
        },
    )

    assert result is None


def test_default_route_finding_is_built_correctly():
    result = check_default_route(
        route_table_id="rtb-123",
        vpc_id="vpc-123",
        route={
            "DestinationCidrBlock": "0.0.0.0/0",
            "GatewayId": "igw-123",
            "State": "active",
        },
    )

    finding = build_default_route_finding(result)

    assert finding.rule_id == "CS-AWS-RT-001"
    assert finding.severity == Severity.LOW
    assert finding.provider == "aws"
    assert finding.resource_type == "route_table"
    assert finding.resource_id == "rtb-123"
    assert finding.evidence["gateway_id"] == "igw-123"
