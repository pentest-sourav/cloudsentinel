from typing import Any

from scanner.aws.services.elasticache import ElastiCacheService


class ElastiCacheDataCollector:
    def __init__(self, service: ElastiCacheService):
        self.service = service
        self._cache_clusters: list[dict[str, Any]] | None = None
        self._replication_groups: list[dict[str, Any]] | None = None

    def collect_cache_clusters(self) -> list[dict[str, Any]]:
        if self._cache_clusters is None:
            raw_clusters = self.service.describe_cache_clusters()

            self._cache_clusters = [
                self._normalize_cache_cluster(cluster)
                for cluster in raw_clusters
            ]

        return self._cache_clusters

    def collect_replication_groups(
        self,
    ) -> list[dict[str, Any]]:
        if self._replication_groups is None:
            raw_groups = self.service.describe_replication_groups()

            self._replication_groups = [
                self._normalize_replication_group(group)
                for group in raw_groups
            ]

        return self._replication_groups

    @staticmethod
    def _normalize_cache_cluster(
        cluster: dict[str, Any],
    ) -> dict[str, Any]:
        resource_id = cluster.get("CacheClusterId")

        return {
            "resource_kind": "cache_cluster",
            "resource_id": resource_id,
            "cache_cluster_id": resource_id,
            "resource_arn": cluster.get("ARN"),
            "engine": cluster.get("Engine"),
            "engine_version": cluster.get("EngineVersion"),
            "cache_cluster_status": cluster.get(
                "CacheClusterStatus"
            ),
            "auto_minor_version_upgrade": cluster.get(
                "AutoMinorVersionUpgrade"
            ),
            "snapshot_retention_limit": cluster.get(
                "SnapshotRetentionLimit"
            ),
            "cache_subnet_group_name": cluster.get(
                "CacheSubnetGroupName"
            ),
            "num_cache_nodes": cluster.get("NumCacheNodes"),
            "resource": cluster,
        }

    @staticmethod
    def _normalize_replication_group(
        group: dict[str, Any],
    ) -> dict[str, Any]:
        resource_id = group.get("ReplicationGroupId")

        return {
            "resource_kind": "replication_group",
            "resource_id": resource_id,
            "replication_group_id": resource_id,
            "resource_arn": group.get("ARN"),
            "engine": group.get("Engine"),
            "engine_version": group.get("EngineVersion"),
            "status": group.get("Status"),
            "automatic_failover": group.get(
                "AutomaticFailover"
            ),
            "multi_az": group.get("MultiAZ"),
            "transit_encryption_enabled": group.get(
                "TransitEncryptionEnabled"
            ),
            "at_rest_encryption_enabled": group.get(
                "AtRestEncryptionEnabled"
            ),
            "auth_token_enabled": group.get("AuthTokenEnabled"),
            "cache_subnet_group_name": group.get(
                "CacheSubnetGroupName"
            ),
            "snapshot_retention_limit": group.get(
                "SnapshotRetentionLimit"
            ),
            "num_node_groups": group.get("NumNodeGroups"),
            "replicas_per_node_group": group.get(
                "ReplicasPerNodeGroup"
            ),
            "resource": group,
        }

    def collect(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "elasticache_cache_clusters": (
                self.collect_cache_clusters()
            ),
            "elasticache_replication_groups": (
                self.collect_replication_groups()
            ),
        }
