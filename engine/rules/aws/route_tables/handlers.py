from scanner.aws.collectors.route_tables import RouteTableDataCollector


def collect_routes(
    collector: RouteTableDataCollector,
) -> list[dict]:
    route_tables = collector.collect_route_tables()

    normalized_routes = []

    for route_table in route_tables:
        for route in route_table.get("routes", []):
            normalized_routes.append(
                {
                    "route_table_id": route_table["route_table_id"],
                    "vpc_id": route_table["vpc_id"],
                    "route": route,
                }
            )

    return normalized_routes


ROUTE_TABLE_DATA_SOURCE_HANDLERS = {
    "routes": collect_routes,
}
