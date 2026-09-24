from typing import Any

from scanner.aws.services.rds import RDSService


class RDSDataCollector:
    """
    Normalize AWS RDS data for CloudSentinel security rules.

    The collector does not evaluate security conditions.
    It only converts AWS API responses into a stable,
    rule-friendly structure.
    """

    def __init__(self, service: RDSService):
        self.service = service
        self._instances_cache: list[dict[str, Any]] | None = None

    def _get_instances(self) -> list[dict[str, Any]]:
        """
        Discover RDS instances once and cache the result.
        """
        if self._instances_cache is None:
            self._instances_cache = self.service.describe_db_instances()

        return self._instances_cache

    def collect_instances(self) -> list[dict[str, Any]]:
        """
        Return normalized RDS DB instance data.

        Optional AWS fields are preserved as None when unavailable
        instead of being converted into security-negative values.
        This prevents missing API data from creating false positives.
        """
        normalized: list[dict[str, Any]] = []

        for instance in self._get_instances():
            instance_id = instance.get("DBInstanceIdentifier")

            if not instance_id:
                continue

            normalized.append(
                {
                    "db_instance_id": instance_id,
                    "engine": instance.get("Engine"),
                    "engine_version": instance.get("EngineVersion"),
                    "publicly_accessible": instance.get(
                        "PubliclyAccessible"
                    ),
                    "storage_encrypted": instance.get(
                        "StorageEncrypted"
                    ),
                    "backup_retention_period": instance.get(
                        "BackupRetentionPeriod"
                    ),
                    "multi_az": instance.get("MultiAZ"),
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
                }
            )

        return normalized
