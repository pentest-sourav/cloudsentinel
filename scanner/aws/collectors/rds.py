from typing import Any

from scanner.aws.services.rds import RDSService


class RDSDataCollector:
    """
    Normalize AWS RDS resources into stable rule-friendly contracts.

    Collection is cached per scan so the same AWS resource is not
    repeatedly fetched by individual rules.
    """

    def __init__(self, service: RDSService):
        self.service = service

        self._instances_cache: list[dict[str, Any]] | None = None
        self._clusters_cache: list[dict[str, Any]] | None = None
        self._snapshots_cache: list[dict[str, Any]] | None = None
        self._cluster_snapshots_cache: list[dict[str, Any]] | None = None
        self._subscriptions_cache: list[dict[str, Any]] | None = None
        self._proxies_cache: list[dict[str, Any]] | None = None
        self._subnet_groups_cache: list[dict[str, Any]] | None = None
        self._parameter_groups_cache: list[dict[str, Any]] | None = None
        self._security_groups_cache: list[dict[str, Any]] | None = None

        self._snapshot_attributes_cache: dict[str, dict[str, Any]] = {}
        self._cluster_snapshot_attributes_cache: dict[
            str, dict[str, Any]
        ] = {}
        self._tags_cache: dict[str, list[dict[str, Any]]] = {}

    def _get_instances(self) -> list[dict[str, Any]]:
        if self._instances_cache is None:
            self._instances_cache = self.service.describe_db_instances()
        return self._instances_cache

    def _get_clusters(self) -> list[dict[str, Any]]:
        if self._clusters_cache is None:
            self._clusters_cache = self.service.describe_db_clusters()
        return self._clusters_cache

    def _get_snapshots(self) -> list[dict[str, Any]]:
        if self._snapshots_cache is None:
            self._snapshots_cache = self.service.describe_db_snapshots()
        return self._snapshots_cache

    def _get_cluster_snapshots(self) -> list[dict[str, Any]]:
        if self._cluster_snapshots_cache is None:
            self._cluster_snapshots_cache = (
                self.service.describe_db_cluster_snapshots()
            )
        return self._cluster_snapshots_cache

    def _get_subscriptions(self) -> list[dict[str, Any]]:
        if self._subscriptions_cache is None:
            self._subscriptions_cache = (
                self.service.describe_event_subscriptions()
            )
        return self._subscriptions_cache

    def _get_proxies(self) -> list[dict[str, Any]]:
        if self._proxies_cache is None:
            self._proxies_cache = self.service.describe_db_proxies()
        return self._proxies_cache

    def _get_subnet_groups(self) -> list[dict[str, Any]]:
        if self._subnet_groups_cache is None:
            self._subnet_groups_cache = (
                self.service.describe_db_subnet_groups()
            )
        return self._subnet_groups_cache

    def _get_parameter_groups(self) -> list[dict[str, Any]]:
        if self._parameter_groups_cache is None:
            self._parameter_groups_cache = (
                self.service.describe_db_parameter_groups()
            )
        return self._parameter_groups_cache

    def _get_security_groups(self) -> list[dict[str, Any]]:
        if self._security_groups_cache is None:
            self._security_groups_cache = (
                self.service.describe_db_security_groups()
            )
        return self._security_groups_cache

    @staticmethod
    def _normalize_tags(tags: Any) -> list[dict[str, str]]:
        if not tags:
            return []

        normalized: list[dict[str, str]] = []

        for tag in tags:
            key = tag.get("Key")
            value = tag.get("Value", "")

            if key is None:
                continue

            normalized.append(
                {
                    "key": str(key),
                    "value": str(value),
                }
            )

        return normalized

    def _tags(self, arn: str | None) -> list[dict[str, str]] | None:
        if not arn:
            return None

        if arn not in self._tags_cache:
            self._tags_cache[arn] = self._normalize_tags(
                self.service.list_tags_for_resource(arn)
            )

        return self._tags_cache[arn]

    def collect_instances(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for instance in self._get_instances():
            instance_id = instance.get("DBInstanceIdentifier")

            if not instance_id:
                continue

            instance_arn = instance.get("DBInstanceArn")

            normalized.append(
                {
                    "db_instance_id": instance_id,
                    "db_instance_arn": instance_arn,
                    "engine": instance.get("Engine"),
                    "engine_version": instance.get("EngineVersion"),
                    "db_name": instance.get("DBName"),
                    "db_instance_class": instance.get(
                        "DBInstanceClass"
                    ),
                    "db_instance_status": instance.get(
                        "DBInstanceStatus"
                    ),
                    "publicly_accessible": instance.get(
                        "PubliclyAccessible"
                    ),
                    "storage_encrypted": instance.get(
                        "StorageEncrypted"
                    ),
                    "kms_key_id": instance.get("KmsKeyId"),
                    "backup_retention_period": instance.get(
                        "BackupRetentionPeriod"
                    ),
                    "preferred_backup_window": instance.get(
                        "PreferredBackupWindow"
                    ),
                    "multi_az": instance.get("MultiAZ"),
                    "availability_zone": instance.get(
                        "AvailabilityZone"
                    ),
                    "deletion_protection": instance.get(
                        "DeletionProtection"
                    ),
                    "auto_minor_version_upgrade": instance.get(
                        "AutoMinorVersionUpgrade"
                    ),
                    "iam_database_authentication_enabled": instance.get(
                        "IAMDatabaseAuthenticationEnabled"
                    ),
                    "enabled_cloudwatch_logs_exports": instance.get(
                        "EnabledCloudwatchLogsExports"
                    ),
                    "storage_type": instance.get("StorageType"),
                    "allocated_storage": instance.get(
                        "AllocatedStorage"
                    ),
                    "monitoring_interval": instance.get(
                        "MonitoringInterval"
                    ),
                    "port": instance.get("DbInstancePort"),
                    "admin_username": instance.get("MasterUsername"),
                    "db_cluster_identifier": instance.get(
                        "DBClusterIdentifier"
                    ),
                    "db_subnet_group": instance.get("DBSubnetGroup"),
                    "vpc_security_groups": instance.get(
                        "VpcSecurityGroups"
                    ),
                    "copy_tags_to_snapshot": instance.get(
                        "CopyTagsToSnapshot"
                    ),
                    "ca_certificate_identifier": instance.get(
                        "CACertificateIdentifier"
                    ),
                    "preferred_maintenance_window": instance.get(
                        "PreferredMaintenanceWindow"
                    ),
                    "tags": self._tags(instance_arn),
                }
            )

        return normalized

    def collect_clusters(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for cluster in self._get_clusters():
            cluster_id = cluster.get("DBClusterIdentifier")

            if not cluster_id:
                continue

            normalized.append(
                {
                    "db_cluster_id": cluster_id,
                    "db_cluster_arn": cluster.get("DBClusterArn"),
                    "engine": cluster.get("Engine"),
                    "engine_version": cluster.get("EngineVersion"),
                    "status": cluster.get("Status"),
                    "port": cluster.get("Port"),
                    "storage_encrypted": cluster.get(
                        "StorageEncrypted"
                    ),
                    "kms_key_id": cluster.get("KmsKeyId"),
                    "backup_retention_period": cluster.get(
                        "BackupRetentionPeriod"
                    ),
                    "deletion_protection": cluster.get(
                        "DeletionProtection"
                    ),
                    "iam_database_authentication_enabled": cluster.get(
                        "IAMDatabaseAuthenticationEnabled"
                    ),
                    "copy_tags_to_snapshot": cluster.get(
                        "CopyTagsToSnapshot"
                    ),
                    "engine_mode": cluster.get("EngineMode"),
                    "auto_minor_version_upgrade": cluster.get(
                        "AutoMinorVersionUpgrade"
                    ),
                    "availability_zones": cluster.get(
                        "AvailabilityZones"
                    ),
                    "enabled_cloudwatch_logs_exports": cluster.get(
                        "EnabledCloudwatchLogsExports"
                    ),
                    "master_username": cluster.get("MasterUsername"),
                    "tags": self._tags(cluster.get("DBClusterArn")),
                }
            )

        return normalized

    def collect_snapshots(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for snapshot in self._get_snapshots():
            snapshot_id = snapshot.get("DBSnapshotIdentifier")

            if not snapshot_id:
                continue

            attributes = self._snapshot_attributes_cache.get(snapshot_id)

            if attributes is None:
                attributes = self.service.describe_db_snapshot_attributes(
                    snapshot_id
                )
                self._snapshot_attributes_cache[snapshot_id] = attributes

            values = {
                attribute.get("AttributeName"): attribute.get(
                    "AttributeValues", []
                )
                for attribute in attributes.get("DBSnapshotAttributesResult", {})
                .get("DBSnapshotAttributes", [])
            }

            normalized.append(
                {
                    "snapshot_id": snapshot_id,
                    "snapshot_arn": snapshot.get("DBSnapshotArn"),
                    "db_instance_identifier": snapshot.get(
                        "DBInstanceIdentifier"
                    ),
                    "engine": snapshot.get("Engine"),
                    "engine_version": snapshot.get("EngineVersion"),
                    "encrypted": snapshot.get("Encrypted"),
                    "kms_key_id": snapshot.get("KmsKeyId"),
                    "snapshot_type": snapshot.get("SnapshotType"),
                    "status": snapshot.get("Status"),
                    "shared_accounts": values.get("restore", []),
                    "tags": self._tags(snapshot.get("DBSnapshotArn")),
                }
            )

        return normalized

    def collect_cluster_snapshots(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for snapshot in self._get_cluster_snapshots():
            snapshot_id = snapshot.get("DBClusterSnapshotIdentifier")

            if not snapshot_id:
                continue

            attributes = self._cluster_snapshot_attributes_cache.get(
                snapshot_id
            )

            if attributes is None:
                attributes = (
                    self.service.describe_db_cluster_snapshot_attributes(
                        snapshot_id
                    )
                )
                self._cluster_snapshot_attributes_cache[
                    snapshot_id
                ] = attributes

            values = {
                attribute.get("AttributeName"): attribute.get(
                    "AttributeValues", []
                )
                for attribute in attributes.get(
                    "DBClusterSnapshotAttributesResult",
                    {},
                ).get("DBClusterSnapshotAttributes", [])
            }

            normalized.append(
                {
                    "snapshot_id": snapshot_id,
                    "snapshot_arn": snapshot.get("DBClusterSnapshotArn"),
                    "db_cluster_identifier": snapshot.get(
                        "DBClusterIdentifier"
                    ),
                    "engine": snapshot.get("Engine"),
                    "engine_version": snapshot.get("EngineVersion"),
                    "encrypted": snapshot.get("StorageEncrypted"),
                    "kms_key_id": snapshot.get("KmsKeyId"),
                    "status": snapshot.get("Status"),
                    "shared_accounts": values.get("restore", []),
                    "tags": self._tags(
                        snapshot.get("DBClusterSnapshotArn")
                    ),
                }
            )

        return normalized

    def collect_event_subscriptions(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for subscription in self._get_subscriptions():
            name = subscription.get("CustSubscriptionId")

            if not name:
                continue

            normalized.append(
                {
                    "subscription_id": name,
                    "status": subscription.get("Status"),
                    "source_type": subscription.get("SourceType"),
                    "source_ids": subscription.get("SourceIdsList", []),
                    "event_categories": subscription.get(
                        "EventCategoriesList",
                        [],
                    ),
                    "enabled": subscription.get("Enabled"),
                    "sns_topic_arn": subscription.get("SnsTopicArn"),
                }
            )

        return normalized

    def collect_proxies(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for proxy in self._get_proxies():
            name = proxy.get("DBProxyName")

            if not name:
                continue

            normalized.append(
                {
                    "proxy_name": name,
                    "proxy_arn": proxy.get("DBProxyArn"),
                    "status": proxy.get("Status"),
                    "require_tls": proxy.get("RequireTLS"),
                    "engine_family": proxy.get("EngineFamily"),
                    "debug_logging": proxy.get("DebugLogging"),
                    "idle_client_timeout": proxy.get(
                        "IdleClientTimeout"
                    ),
                    "vpc_id": proxy.get("VpcId"),
                    "tags": self._tags(proxy.get("DBProxyArn")),
                }
            )

        return normalized

    def collect_subnet_groups(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for group in self._get_subnet_groups():
            name = group.get("DBSubnetGroupName")

            if not name:
                continue

            normalized.append(
                {
                    "subnet_group_name": name,
                    "arn": group.get("DBSubnetGroupArn"),
                    "description": group.get("DBSubnetGroupDescription"),
                    "vpc_id": group.get("VpcId"),
                    "subnets": group.get("Subnets", []),
                    "tags": self._tags(group.get("DBSubnetGroupArn")),
                }
            )

        return normalized

    def collect_parameter_groups(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for group in self._get_parameter_groups():
            name = group.get("DBParameterGroupName")

            if not name:
                continue

            normalized.append(
                {
                    "parameter_group_name": name,
                    "arn": group.get("DBParameterGroupArn"),
                    "family": group.get("DBParameterGroupFamily"),
                    "description": group.get(
                        "Description"
                    ),
                    "tags": self._tags(group.get("DBParameterGroupArn")),
                }
            )

        return normalized

    def collect_security_groups(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for group in self._get_security_groups():
            name = group.get("DBSecurityGroupName")

            if not name:
                continue

            normalized.append(
                {
                    "security_group_name": name,
                    "arn": group.get("DBSecurityGroupArn"),
                    "description": group.get(
                        "DBSecurityGroupDescription"
                    ),
                    "vpc_id": group.get("VpcId"),
                    "tags": self._tags(group.get("DBSecurityGroupArn")),
                }
            )

        return normalized
