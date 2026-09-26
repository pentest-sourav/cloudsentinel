from typing import Any

from scanner.aws.services.documentdb import DocumentDBService


class DocumentDBDataCollector:
    """
    Normalize AWS DocumentDB resources into stable rule-friendly contracts.

    Collection is cached per scan so multiple rules reuse the same AWS
    responses instead of repeatedly calling the DocumentDB API.
    """

    def __init__(self, service: DocumentDBService):
        self.service = service

        self._clusters_cache: list[dict[str, Any]] | None = None
        self._snapshots_cache: list[dict[str, Any]] | None = None
        self._snapshot_attributes_cache: dict[str, dict[str, Any]] = {}
        self._parameters_cache: dict[str, list[dict[str, Any]]] = {}

    def _get_clusters(self) -> list[dict[str, Any]]:
        if self._clusters_cache is None:
            self._clusters_cache = self.service.describe_db_clusters()
        return self._clusters_cache

    def _get_snapshots(self) -> list[dict[str, Any]]:
        if self._snapshots_cache is None:
            self._snapshots_cache = (
                self.service.describe_db_cluster_snapshots()
            )
        return self._snapshots_cache

    def _get_snapshot_attributes(
        self,
        snapshot_id: str | None,
    ) -> dict[str, Any] | None:
        if not snapshot_id:
            return None

        if snapshot_id not in self._snapshot_attributes_cache:
            self._snapshot_attributes_cache[snapshot_id] = (
                self.service.describe_db_cluster_snapshot_attributes(
                    snapshot_id
                )
            )

        return self._snapshot_attributes_cache[snapshot_id]

    def _get_parameters(
        self,
        parameter_group_name: str | None,
    ) -> list[dict[str, Any]] | None:
        if not parameter_group_name:
            return None

        if parameter_group_name not in self._parameters_cache:
            self._parameters_cache[parameter_group_name] = (
                self.service.describe_db_cluster_parameters(
                    parameter_group_name
                )
            )

        return self._parameters_cache[parameter_group_name]

    @staticmethod
    def _extract_tls_parameter(
        parameters: list[dict[str, Any]] | None,
    ) -> str | None:
        if parameters is None:
            return None

        for parameter in parameters:
            if str(parameter.get("ParameterName", "")).lower() == "tls":
                value = parameter.get("ParameterValue")
                return str(value).strip().lower() if value is not None else None

        return None

    @staticmethod
    def _extract_audit_logs(
        cluster: dict[str, Any],
    ) -> list[str]:
        values = cluster.get("EnabledCloudwatchLogsExports") or []
        return [
            str(value).strip().lower()
            for value in values
            if str(value).strip()
        ]

    def collect_clusters(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for cluster in self._get_clusters():
            cluster_id = cluster.get("DBClusterIdentifier")
            if not cluster_id:
                continue

            parameter_groups = cluster.get("DBClusterParameterGroup") or []
            parameter_group_name: str | None = None
            parameter_apply_status: str | None = None

            if parameter_groups:
                first_group = parameter_groups[0] or {}
                parameter_group_name = first_group.get(
                    "DBClusterParameterGroupName"
                )
                parameter_apply_status = first_group.get(
                    "ParameterApplyStatus"
                )

            parameters = self._get_parameters(parameter_group_name)

            normalized.append(
                {
                    "db_cluster_id": cluster_id,
                    "db_cluster_arn": cluster.get("DBClusterArn"),
                    "engine": cluster.get("Engine"),
                    "engine_version": cluster.get("EngineVersion"),
                    "status": cluster.get("Status"),
                    "storage_encrypted": cluster.get("StorageEncrypted"),
                    "kms_key_id": cluster.get("KmsKeyId"),
                    "backup_retention_period": cluster.get(
                        "BackupRetentionPeriod"
                    ),
                    "deletion_protection": cluster.get(
                        "DeletionProtection"
                    ),
                    "enabled_cloudwatch_logs_exports": (
                        self._extract_audit_logs(cluster)
                    ),
                    "parameter_group_name": parameter_group_name,
                    "parameter_apply_status": parameter_apply_status,
                    "tls_parameter": self._extract_tls_parameter(parameters),
                    "tag_data_available": True,
                }
            )

        return normalized

    def collect_snapshots(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for snapshot in self._get_snapshots():
            # Security Hub DocumentDB.3 evaluates manual snapshots only.
            if str(snapshot.get("SnapshotType", "")).lower() != "manual":
                continue

            snapshot_id = snapshot.get("DBClusterSnapshotIdentifier")
            if not snapshot_id:
                continue

            attributes = self._get_snapshot_attributes(snapshot_id)

            attribute_values = {
                attribute.get("AttributeName"): attribute.get(
                    "AttributeValues",
                    [],
                )
                for attribute in (
                    (attributes or {}).get(
                        "DBClusterSnapshotAttributesResult",
                        {},
                    ).get(
                        "DBClusterSnapshotAttributes",
                        [],
                    )
                )
            }

            restore_values = attribute_values.get("restore", [])
            shared_accounts = list(restore_values or [])

            normalized.append(
                {
                    "snapshot_id": snapshot_id,
                    "snapshot_arn": snapshot.get("DBClusterSnapshotArn"),
                    "db_cluster_identifier": snapshot.get(
                        "DBClusterIdentifier"
                    ),
                    "engine": snapshot.get("Engine"),
                    "engine_version": snapshot.get("EngineVersion"),
                    "storage_encrypted": snapshot.get("StorageEncrypted"),
                    "kms_key_id": snapshot.get("KmsKeyId"),
                    "status": snapshot.get("Status"),
                    "snapshot_type": snapshot.get("SnapshotType"),
                    "shared_accounts": shared_accounts,
                }
            )

        return normalized
