from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class NeptuneService:
    """
    Read-only Amazon Neptune discovery service.

    AWS collection is isolated from CloudSentinel rule evaluation.
    """

    def __init__(self, session):
        self.session = session
        self.neptune_client = create_aws_client(session, "neptune")

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get(
                "Message",
                "AWS request failed",
            )
            raise RuntimeError(
                f"Neptune {operation} failed: "
                f"{code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during Neptune "
            f"{operation}: {exc}"
        ) from exc

    def describe_db_clusters(self) -> list[dict[str, Any]]:
        try:
            paginator = self.neptune_client.get_paginator(
                "describe_db_clusters"
            )

            clusters: list[dict[str, Any]] = []

            for page in paginator.paginate():
                clusters.extend(
                    page.get("DBClusters", [])
                )

            return clusters

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "DB cluster discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_db_instances(self) -> list[dict[str, Any]]:
        try:
            paginator = self.neptune_client.get_paginator(
                "describe_db_instances"
            )

            instances: list[dict[str, Any]] = []

            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "engine",
                        "Values": ["neptune"],
                    }
                ]
            ):
                instances.extend(
                    page.get("DBInstances", [])
                )

            return instances

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "DB instance discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_db_cluster_snapshots(
        self,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.neptune_client.get_paginator(
                "describe_db_cluster_snapshots"
            )

            snapshots: list[dict[str, Any]] = []

            for page in paginator.paginate():
                snapshots.extend(
                    page.get("DBClusterSnapshots", [])
                )

            return snapshots

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                "DB cluster snapshot discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_db_cluster_snapshot_attributes(
        self,
        snapshot_identifier: str,
    ) -> dict[str, Any]:
        try:
            return self.neptune_client.describe_db_cluster_snapshot_attributes(
                DBClusterSnapshotIdentifier=snapshot_identifier,
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_api_error(
                f"snapshot attribute discovery for "
                f"{snapshot_identifier}",
                exc,
            )
            raise AssertionError("unreachable")
