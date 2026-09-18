from typing import Any

from botocore.exceptions import BotoCoreError, ClientError


class RDSService:
    """
    Read-only AWS RDS discovery service.

    This service is responsible only for collecting RDS
    configuration data from AWS. Security evaluation is
    handled separately by CloudSentinel rules.
    """

    def __init__(self, session):
        self.session = session
        self.rds_client = session.client("rds")

    def describe_db_instances(self) -> list[dict[str, Any]]:
        """
        Discover all RDS DB instances in the current AWS region.
        """
        try:
            paginator = self.rds_client.get_paginator(
                "describe_db_instances"
            )

            instances: list[dict[str, Any]] = []

            for page in paginator.paginate():
                instances.extend(
                    page.get("DBInstances", [])
                )

            return instances

        except ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"RDS DB instance discovery failed: "
                f"{code}: {message}"
            ) from exc

        except BotoCoreError as exc:
            raise RuntimeError(
                f"AWS SDK error during RDS DB instance "
                f"discovery: {exc}"
            ) from exc
