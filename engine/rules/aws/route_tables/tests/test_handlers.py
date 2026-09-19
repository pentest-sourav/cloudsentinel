from unittest.mock import Mock

from engine.rules.aws.route_tables.handlers import collect_routes


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
    assert result[0]["vpc_id"] == "vpc-123"
    assert result[0]["route"]["GatewayId"] == "local"

    assert result[1]["route_table_id"] == "rtb-123"
    assert result[1]["vpc_id"] == "vpc-123"
    assert result[1]["route"]["GatewayId"] == "igw-123"


def test_collect_routes_handles_empty_route_tables():
    collector = Mock()

    collector.collect_route_tables.return_value = []

    result = collect_routes(collector)

    assert result == []


def test_collect_routes_handles_route_table_without_routes():
    collector = Mock()

    collector.collect_route_tables.return_value = [
        {
            "route_table_id": "rtb-123",
            "vpc_id": "vpc-123",
            "routes": [],
        }
    ]

    result = collect_routes(collector)

    assert result == []
