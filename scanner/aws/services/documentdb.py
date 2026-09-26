from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class DocumentDBService:
    """
    Read-only AWS DocumentDB discovery service.

    AWS API discovery is kept separate from security evaluation.
    Paginated APIs are fully consumed and AWS errors are normalized into
    stable RuntimeError messages for the scanner layer.
    """

    def __init__(self, session):
        self.session = session
        self.docdb_client = create_aws_client(session, "docdb")

    @staticmethod
    def _raise_discovery_error(resource: str, exc: Exception) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get("Error", {})
            code = error.get("Code", "UnknownError")
            message = error.get("Message", "AWS request failed")
            raise RuntimeError(
                f"DocumentDB {resource} discovery failed: "
                f"{code}: {message}"
            ) from exc

        raise RuntimeError(
            f"AWS SDK error during DocumentDB {resource} discovery: {exc}"
        ) from exc

    def _paginate(
        self,
        operation: str,
        result_key: str,
        resource: str,
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        try:
            paginator = self.docdb_client.get_paginator(operation)
            results: list[dict[str, Any]] = []

            for page in paginator.paginate(**kwargs):
                results.extend(page.get(result_key, []))

            return results

        except (ClientError, BotoCoreError) as exc:
            self._raise_discovery_error(resource, exc)
            raise AssertionError("unreachable")

    def describe_db_clusters(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_clusters",
            "DBClusters",
            "DB cluster",
        )

    def describe_db_cluster_snapshots(self) -> list[dict[str, Any]]:
        return self._paginate(
            "describe_db_cluster_snapshots",
            "DBClusterSnapshots",
            "DB cluster snapshot",
        )

    def describe_db_cluster_snapshot_attributes(
        self,
        snapshot_identifier: str,
    ) -> dict[str, Any]:
        try:
            return self.docdb_client.describe_db_cluster_snapshot_attributes(
                DBClusterSnapshotIdentifier=snapshot_identifier,
            )

        except (ClientError, BotoCoreError) as exc:
            self._raise_discovery_error(
                f"cluster snapshot attributes ({snapshot_identifier})",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_db_cluster_parameters(
        self,
        parameter_group_name: str,
    ) -> list[dict[str, Any]]:
        if not parameter_group_name:
            return []

        try:
            parameters: list[dict[str, Any]] = []
            marker: str | None = None

            while True:
                kwargs: dict[str, Any] = {
                    "DBClusterParameterGroupName": parameter_group_name,
                    "MaxRecords": 100,
                }

                if marker:
                    kwargs["Marker"] = marker

                response = self.docdb_client.describe_db_cluster_parameters(
                    **kwargs,
                )

                parameters.extend(response.get("Parameters", []))

                marker = response.get("Marker")
                if not marker:
                    break

            return parameters

        except (ClientError, BotoCoreError) as exc:
            self._raise_discovery_error(
                f"cluster parameters ({parameter_group_name})",
                exc,
            )
            raise AssertionError("unreachable")
