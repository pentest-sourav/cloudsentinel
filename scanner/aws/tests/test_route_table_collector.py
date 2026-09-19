from unittest.mock import Mock

from scanner.aws.collectors.route_tables import RouteTableDataCollector


def test_collect_route_tables_normalizes_data():
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
                },
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "igw-123",
                    "State": "active",
                },
            ],
            "Associations": [
                {
                    "RouteTableAssociationId": "rtbassoc-123",
                    "Main": True,
                    "AssociationState": {
                        "State": "associated"
                    },
                }
            ],
            "PropagatingVgws": [],
        }
    ]

    collector = RouteTableDataCollector(service)

    result = collector.collect_route_tables()

    assert len(result) == 1

    route_table = result[0]

    assert route_table["route_table_id"] == "rtb-123"
    assert route_table["vpc_id"] == "vpc-123"

    assert len(route_table["routes"]) == 2
    assert route_table["routes"][1]["GatewayId"] == "igw-123"

    assert len(route_table["associations"]) == 1
    assert route_table["associations"][0]["Main"] is True

    assert route_table["propagating_vgws"] == []


def test_collect_route_tables_skips_missing_route_table_id():
    service = Mock()

    service.describe_route_tables.return_value = [
        {
            "VpcId": "vpc-123",
            "Routes": [],
            "Associations": [],
            "PropagatingVgws": [],
        }
    ]

    collector = RouteTableDataCollector(service)

    result = collector.collect_route_tables()

    assert result == []


def test_collect_route_tables_uses_cache():
    service = Mock()

    service.describe_route_tables.return_value = [
        {
            "RouteTableId": "rtb-123",
            "VpcId": "vpc-123",
            "Routes": [],
            "Associations": [],
            "PropagatingVgws": [],
        }
    ]

    collector = RouteTableDataCollector(service)

    first = collector.collect_route_tables()
    second = collector.collect_route_tables()

    assert first == second

    service.describe_route_tables.assert_called_once()
