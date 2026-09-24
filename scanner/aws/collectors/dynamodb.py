from typing import Any

from scanner.aws.services.dynamodb import DynamoDBService


class DynamoDBDataCollector:
    """
    Normalize AWS DynamoDB and DAX configuration for
    CloudSentinel rules.
    """

    def __init__(self, service: DynamoDBService):
        self.service = service

        self._tables_cache: list[str] | None = None
        self._table_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}
        self._continuous_backups_cache: dict[
            str,
            dict[str, Any],
        ] = {}
        self._tags_cache: dict[
            str,
            list[dict[str, Any]],
        ] = {}
        self._scalable_targets_cache: dict[
            str,
            dict[str, list[dict[str, Any]]],
        ] = {}
        self._scaling_policies_cache: dict[
            str,
            dict[str, list[dict[str, Any]]],
        ] = {}
        self._dax_clusters_cache: list[
            dict[str, Any]
        ] | None = None
        self._backup_resources_cache: list[
            dict[str, Any]
        ] | None = None

    def _get_tables(self) -> list[str]:
        if self._tables_cache is None:
            self._tables_cache = self.service.list_tables()

        return self._tables_cache

    def _get_table_details(
        self,
        table_name: str,
    ) -> dict[str, Any]:
        if table_name not in self._table_details_cache:
            self._table_details_cache[table_name] = (
                self.service.describe_table(table_name)
            )

        return self._table_details_cache[table_name]

    def _get_continuous_backups(
        self,
        table_name: str,
    ) -> dict[str, Any]:
        if table_name not in self._continuous_backups_cache:
            self._continuous_backups_cache[table_name] = (
                self.service.describe_continuous_backups(
                    table_name
                )
            )

        return self._continuous_backups_cache[table_name]

    def _get_tags(
        self,
        table_arn: str,
    ) -> list[dict[str, Any]]:
        if table_arn not in self._tags_cache:
            self._tags_cache[table_arn] = (
                self.service.list_table_tags(table_arn)
            )

        return self._tags_cache[table_arn]

    def _get_scalable_targets(
        self,
        table_name: str,
    ) -> dict[str, list[dict[str, Any]]]:
        if table_name not in self._scalable_targets_cache:
            self._scalable_targets_cache[table_name] = (
                self.service.describe_scalable_targets(
                    table_name
                )
            )

        return self._scalable_targets_cache[table_name]

    def _get_scaling_policies(
        self,
        table_name: str,
    ) -> dict[str, list[dict[str, Any]]]:
        if table_name not in self._scaling_policies_cache:
            self._scaling_policies_cache[table_name] = (
                self.service.describe_scaling_policies(
                    table_name
                )
            )

        return self._scaling_policies_cache[table_name]

    def _get_dax_clusters(self) -> list[dict[str, Any]]:
        if self._dax_clusters_cache is None:
            self._dax_clusters_cache = (
                self.service.list_dax_clusters()
            )

        return self._dax_clusters_cache

    def _get_backup_resources(
        self,
    ) -> list[dict[str, Any]]:
        if self._backup_resources_cache is None:
            self._backup_resources_cache = (
                self.service.list_backup_protected_resources()
            )

        return self._backup_resources_cache

    @staticmethod
    def _is_provisioned_table(
        billing_mode: str | None,
    ) -> bool:
        return billing_mode == "PROVISIONED"

    @staticmethod
    def _is_provisioned_with_autoscaling(
        table: dict[str, Any],
        scalable_targets: dict[str, list[dict[str, Any]]],
        scaling_policies: dict[str, list[dict[str, Any]]],
    ) -> bool:
        billing_mode_summary = table.get(
            "BillingModeSummary",
            {},
        )

        if not isinstance(billing_mode_summary, dict):
            billing_mode_summary = {}

        billing_mode = billing_mode_summary.get(
            "BillingMode"
        )

        if billing_mode == "PAY_PER_REQUEST":
            return True

        if billing_mode != "PROVISIONED":
            return False

        read_dimension = "dynamodb:table:ReadCapacityUnits"
        write_dimension = "dynamodb:table:WriteCapacityUnits"

        read_targets = scalable_targets.get(
            read_dimension,
            [],
        )
        write_targets = scalable_targets.get(
            write_dimension,
            [],
        )

        read_policies = scaling_policies.get(
            read_dimension,
            [],
        )
        write_policies = scaling_policies.get(
            write_dimension,
            [],
        )

        return bool(
            read_targets
            and write_targets
            and read_policies
            and write_policies
        )

    def collect_tables(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        backup_resources = self._get_backup_resources()

        for table_name in self._get_tables():
            table = self._get_table_details(table_name)

            table_arn = table.get("TableArn")

            if not isinstance(table_arn, str) or not table_arn:
                continue

            billing_mode_summary = table.get(
                "BillingModeSummary",
                {},
            )

            if not isinstance(billing_mode_summary, dict):
                billing_mode_summary = {}

            billing_mode = billing_mode_summary.get(
                "BillingMode"
            )

            scalable_targets: dict[
                str,
                list[dict[str, Any]],
            ] = {}

            scaling_policies: dict[
                str,
                list[dict[str, Any]],
            ] = {}

            if self._is_provisioned_table(billing_mode):
                scalable_targets = self._get_scalable_targets(
                    table_name
                )
                scaling_policies = self._get_scaling_policies(
                    table_name
                )

            normalized.append(
                {
                    "table_name": table_name,
                    "table_arn": table_arn,
                    "table_status": table.get("TableStatus"),
                    "billing_mode": billing_mode,
                    "provisioned_throughput": table.get(
                        "ProvisionedThroughput",
                        {},
                    ),
                    "deletion_protection_enabled": table.get(
                        "DeletionProtectionEnabled",
                        False,
                    ),
                    "continuous_backups": (
                        self._get_continuous_backups(
                            table_name
                        )
                    ),
                    "tags": self._get_tags(table_arn),
                    "scalable_targets": scalable_targets,
                    "scaling_policies": scaling_policies,
                    "autoscaling_enabled": (
                        self._is_provisioned_with_autoscaling(
                            table,
                            scalable_targets,
                            scaling_policies,
                        )
                    ),
                    "backup_resources": backup_resources,
                }
            )

        return normalized

    def collect_dax_clusters(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for cluster in self._get_dax_clusters():
            cluster_arn = cluster.get("ClusterArn")
            cluster_name = cluster.get("ClusterName")

            if not isinstance(cluster_arn, str) or not cluster_arn:
                continue

            normalized.append(
                {
                    "cluster_name": cluster_name,
                    "cluster_arn": cluster_arn,
                    "status": cluster.get("Status"),
                    "sse_description": cluster.get(
                        "SSEDescription",
                        {},
                    ),
                    "cluster_endpoint_encryption_type": (
                        cluster.get(
                            "ClusterEndpointEncryptionType"
                        )
                    ),
                }
            )

        return normalized

    def collect_backup_protected_resources(
        self,
    ) -> list[dict[str, Any]]:
        return self._get_backup_resources()
