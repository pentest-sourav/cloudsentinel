from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class MSKService:
    """
    Read-only Amazon MSK discovery service.

    Retrieves MSK clusters and MSK Connect connectors required
    by CloudSentinel security posture rules.
    """

    def __init__(self, session):
        self.kafka_client = create_aws_client(
            session,
            "kafka",
        )
        self.kafka_connect_client = create_aws_client(
            session,
            "kafkaconnect",
        )

    @staticmethod
    def _raise_api_error(
        operation: str,
        exc: Exception,
    ) -> None:
        if isinstance(exc, ClientError):
            error = exc.response.get(
                "Error",
                {},
            )

            code = error.get(
                "Code",
                "UnknownError",
            )

            message = error.get(
                "Message",
                "AWS request failed",
            )

            raise RuntimeError(
                f"AWS MSK {operation} failed: "
                f"{code}: {message}"
            ) from exc

        if isinstance(exc, BotoCoreError):
            raise RuntimeError(
                f"AWS SDK error during MSK "
                f"{operation}: {exc}"
            ) from exc

        raise RuntimeError(
            f"Unexpected error during MSK "
            f"{operation}: {exc}"
        ) from exc

    def list_clusters(self) -> list[dict[str, Any]]:
        clusters: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "MaxResults": 100,
                }

                if next_token:
                    request["NextToken"] = next_token

                response = self.kafka_client.list_clusters_v2(
                    **request,
                )

                entries = response.get(
                    "ClusterInfoList",
                    [],
                )

                if isinstance(entries, list):
                    clusters.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                returned_token = response.get(
                    "NextToken"
                )

                if (
                    not isinstance(returned_token, str)
                    or not returned_token
                ):
                    break

                next_token = returned_token

            return clusters

        except Exception as exc:
            self._raise_api_error(
                "cluster discovery",
                exc,
            )
            raise AssertionError("unreachable")

    def describe_cluster(
        self,
        cluster_arn: str,
    ) -> dict[str, Any]:
        try:
            response = self.kafka_client.describe_cluster_v2(
                ClusterArn=cluster_arn,
            )

            cluster = response.get(
                "ClusterInfo",
                {},
            )

            if not isinstance(cluster, dict):
                return {}

            return cluster

        except Exception as exc:
            self._raise_api_error(
                f"cluster description for '{cluster_arn}'",
                exc,
            )
            raise AssertionError("unreachable")

    def list_connectors(self) -> list[dict[str, Any]]:
        connectors: list[dict[str, Any]] = []
        next_token: str | None = None

        try:
            while True:
                request: dict[str, Any] = {
                    "maxResults": 100,
                }

                if next_token:
                    request["nextToken"] = next_token

                response = self.kafka_connect_client.list_connectors(
                    **request,
                )

                entries = response.get(
                    "connectors",
                    [],
                )

                if isinstance(entries, list):
                    connectors.extend(
                        entry
                        for entry in entries
                        if isinstance(entry, dict)
                    )

                returned_token = response.get(
                    "nextToken"
                )

                if (
                    not isinstance(returned_token, str)
                    or not returned_token
                ):
                    break

                next_token = returned_token

            return connectors

        except Exception as exc:
            self._raise_api_error(
                "connector discovery",
                exc,
            )
            raise AssertionError("unreachable")
