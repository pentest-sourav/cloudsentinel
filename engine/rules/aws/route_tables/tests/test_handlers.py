from unittest.mock import Mock

from engine.rules.aws.route_tables.handlers import (
    collect_route_table_inventory,
    collect_routes,
)


def test_collect_routes_flattens_route_tables():
    collector = Mock()

    collector.collect_route_tables.return_value = [
        {
            "route_table_id": "rtb-123",
            "vpc_id": "vpc-123",
            "routes": [
                {
                    "DestinationCidrBlock": "10.0.0.0/16",
                    "GatewayId": "local",
                    "State": "active",
                },
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-123",
                    "State": "active",
                },
            ],
        }
    ]

    result = collect_routes(collector)

    assert len(result) == 2
    assert result[0]["route_table_id"] == "rtb-123"
    assert result[1]["route"]["GatewayId"] == "igw-123"


def test_collect_routes_handles_empty_route_tables():
    collector = Mock()
    collector.collect_route_tables.return_value = []

    assert collect_routes(collector) == []


def test_collect_routes_handles_route_table_without_routes():
    collector = Mock()
    collector.collect_route_tables.return_value = [
        {
            "route_table_id": "rtb-123",
            "vpc_id": "vpc-123",
            "routes": [],
        }
    ]

    assert collect_routes(collector) == []


def test_collect_route_table_inventory():
    collector = Mock()

    collector.collect_route_tables.return_value = [
        {
            "route_table_id": "rtb-123",
            "vpc_id": "vpc-123",
            "routes": [],
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        }
    ]

    result = collect_route_table_inventory(collector)

    assert result == [
        {
            "route_table_id": "rtb-123",
            "vpc_id": "vpc-123",
            "tags": [
                {
                    "Key": "Environment",
                    "Value": "prod",
                }
            ],
        }
    ]
