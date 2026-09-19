from typing import Any

from scanner.aws.services.route_tables import RouteTableService


class RouteTableDataCollector:
    """
    Normalizes AWS Route Table configuration data
    for security rules.
    """

    def __init__(self, service: RouteTableService):
        self.service = service
        self._route_tables_cache: list[dict[str, Any]] | None = None

    def _get_route_tables(self) -> list[dict[str, Any]]:
        if self._route_tables_cache is None:
            self._route_tables_cache = (
                self.service.describe_route_tables()
            )

        return self._route_tables_cache

    def collect_route_tables(self) -> list[dict[str, Any]]:
        normalized = []

        for table in self._get_route_tables():
            route_table_id = table.get("RouteTableId")

            if not route_table_id:
                continue

            normalized.append(
                {
                    "route_table_id": route_table_id,
                    "vpc_id": table.get("VpcId"),
                    "routes": table.get("Routes", []),
                    "associations": table.get("Associations", []),
                    "propagating_vgws": table.get(
                        "PropagatingVgws",
                        [],
                    ),
                }
            )

        return normalized
