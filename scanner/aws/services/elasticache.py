from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from scanner.aws.client_factory import create_aws_client


class ElastiCacheService:
    def __init__(self, session):
        self.session = session
        self.elasticache_client = create_aws_client(
            session,
            "elasticache",
        )

    @staticmethod
    def _raise_client_error(operation: str, exc: Exception):
        raise RuntimeError(
            f"ElastiCache {operation} failed: {exc}"
        ) from exc

    def describe_cache_clusters(self) -> list[dict[str, Any]]:
        clusters: list[dict[str, Any]] = []
        marker = None

        try:
            while True:
                kwargs: dict[str, Any] = {
                    "ShowCacheNodeInfo": False,
                    "MaxRecords": 100,
                }

                if marker:
                    kwargs["Marker"] = marker

                response = self.elasticache_client.describe_cache_clusters(
                    **kwargs
                )

                clusters.extend(
                    response.get("CacheClusters", [])
                )

                marker = response.get("Marker")
                if not marker:
                    break

        except (ClientError, BotoCoreError) as exc:
            self._raise_client_error(
                "describe_cache_clusters",
                exc,
            )

        return clusters

    def describe_replication_groups(
        self,
    ) -> list[dict[str, Any]]:
        replication_groups: list[dict[str, Any]] = []
        marker = None

        try:
            while True:
                kwargs: dict[str, Any] = {
                    "MaxRecords": 100,
                }

                if marker:
                    kwargs["Marker"] = marker

                response = (
                    self.elasticache_client.describe_replication_groups(
                        **kwargs
                    )
                )

                replication_groups.extend(
                    response.get("ReplicationGroups", [])
                )

                marker = response.get("Marker")
                if not marker:
                    break

        except (ClientError, BotoCoreError) as exc:
            self._raise_client_error(
                "describe_replication_groups",
                exc,
            )

        return replication_groups
