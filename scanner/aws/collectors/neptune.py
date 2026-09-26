from typing import Any

from scanner.aws.services.neptune import NeptuneService


class NeptuneDataCollector:
    """
    Normalize Amazon Neptune API data for CloudSentinel rules.

    API responses are collected once and cached for the lifetime
    of the collector.
    """

    def __init__(self, service: NeptuneService):
        self.service = service

        self._clusters_cache: list[dict[str, Any]] | None = None
        self._instances_cache: list[dict[str, Any]] | None = None
        self._snapshots_cache: list[dict[str, Any]] | None = None
        self._snapshot_attributes_cache: dict[
            str,
            dict[str, Any],
        ] = {}

    def _get_clusters(self) -> list[dict[str, Any]]:
        if self._clusters_cache is None:
            self._clusters_cache = (
                self.service.describe_db_clusters()
            )

        return self._clusters_cache

    def _get_instances(self) -> list[dict[str, Any]]:
        if self._instances_cache is None:
            self._instances_cache = (
                self.service.describe_db_instances()
            )

        return self._instances_cache

    def _get_snapshots(self) -> list[dict[str, Any]]:
        if self._snapshots_cache is None:
            self._snapshots_cache = (
                self.service.describe_db_cluster_snapshots()
            )

        return self._snapshots_cache

    def _get_snapshot_attributes(
        self,
        snapshot_identifier: str,
    ) -> dict[str, Any]:
        if (
            snapshot_identifier
            not in self._snapshot_attributes_cache
        ):
            self._snapshot_attributes_cache[
                snapshot_identifier
            ] = (
                self.service
                .describe_db_cluster_snapshot_attributes(
                    snapshot_identifier
                )
            )

        return self._snapshot_attributes_cache[
            snapshot_identifier
        ]

    @staticmethod
    def _restore_attribute_is_public(
        attributes_response: dict[str, Any],
    ) -> bool:
        for attribute in attributes_response.get(
            "DBClusterSnapshotAttributesResult", {}
        ).get(
            "DBClusterSnapshotAttributes",
            [],
        ):
            if attribute.get("AttributeName") != "restore":
                continue

            values = attribute.get(
                "AttributeValues",
                [],
            )

            if "all" in values:
                return True

        return False

    def collect_clusters(self) -> list[dict[str, Any]]:
        """
        Return normalized Neptune cluster data.

        Availability zones are derived only from actual Neptune
        DB instance AvailabilityZone values. Missing data is not
        converted into a security-negative value.
        """
        instances_by_cluster: dict[
            str,
            list[dict[str, Any]],
        ] = {}

        for instance in self._get_instances():
            cluster_id = instance.get(
                "DBClusterIdentifier"
            )

            if not cluster_id:
                continue

            instances_by_cluster.setdefault(
                cluster_id,
                [],
            ).append(instance)

        normalized: list[dict[str, Any]] = []

        for cluster in self._get_clusters():
            cluster_id = cluster.get(
                "DBClusterIdentifier"
            )

            if not cluster_id:
                continue

            member_instances = instances_by_cluster.get(
                cluster_id,
                [],
            )

            availability_zones = sorted(
                {
                    instance.get("AvailabilityZone")
                    for instance in member_instances
                    if instance.get("AvailabilityZone")
                }
            )

            normalized.append(
                {
                    "db_cluster_id": cluster_id,
                    "db_cluster_arn": cluster.get(
                        "DBClusterArn"
                    ),
                    "storage_encrypted": cluster.get(
                        "StorageEncrypted"
                    ),
                    "enabled_cloudwatch_logs_exports": (
                        cluster.get(
                            "EnabledCloudwatchLogsExports"
                        )
                    ),
                    "deletion_protection": cluster.get(
                        "DeletionProtection"
                    ),
                    "backup_retention_period": cluster.get(
                        "BackupRetentionPeriod"
                    ),
                    "iam_database_authentication_enabled": (
                        cluster.get(
                            "IAMDatabaseAuthenticationEnabled"
                        )
                    ),
                    "copy_tags_to_snapshot": cluster.get(
                        "CopyTagsToSnapshot"
                    ),
                    "availability_zones": availability_zones,
                    "availability_zone_count": len(
                        availability_zones
                    ),
                }
            )

        return normalized

    def collect_snapshots(self) -> list[dict[str, Any]]:
        """
        Return normalized Neptune DB cluster snapshots.

        Public-access attributes are fetched only for manual
        snapshots because AWS exposes sharing attributes for
        manual snapshots.
        """
        normalized: list[dict[str, Any]] = []

        for snapshot in self._get_snapshots():
            snapshot_id = snapshot.get(
                "DBClusterSnapshotIdentifier"
            )

            if not snapshot_id:
                continue

            snapshot_type = snapshot.get(
                "SnapshotType"
            )

            is_public = False

            if snapshot_type == "manual":
                attributes = self._get_snapshot_attributes(
                    snapshot_id
                )
                is_public = (
                    self._restore_attribute_is_public(
                        attributes
                    )
                )

            normalized.append(
                {
                    "db_cluster_snapshot_id": snapshot_id,
                    "db_cluster_identifier": snapshot.get(
                        "DBClusterIdentifier"
                    ),
                    "snapshot_type": snapshot_type,
                    "storage_encrypted": snapshot.get(
                        "StorageEncrypted"
                    ),
                    "is_public": is_public,
                }
            )

        return normalized
