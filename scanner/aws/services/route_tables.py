from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class RouteTableService:
    """
    Read-only AWS Route Table discovery service.

    This service is responsible only for collecting Route Table
    configuration data. Security evaluation is handled separately
    by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.ec2_client = session.client("ec2")

    def describe_route_tables(self) -> list[dict[str, Any]]:
        """
        Return all Route Tables available to the current AWS account.
        """
        try:
            paginator = self.ec2_client.get_paginator(
                "describe_route_tables"
            )

            route_tables = []

            for page in paginator.paginate():
                route_tables.extend(
                    page.get("RouteTables", [])
                )

            return route_tables

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"Route Table discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                "AWS SDK error during Route Table discovery: "
                f"{exc}"
            ) from exc
