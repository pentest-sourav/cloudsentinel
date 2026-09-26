from typing import Any

from scanner.aws.services.msk import MSKService


class MSKDataCollector:
    """
    Normalize Amazon MSK and MSK Connect configuration
    for CloudSentinel security rules.
    """

    def __init__(self, service: MSKService):
        self.service = service

        self._clusters_cache: list[dict[str, Any]] | None = None
        self._cluster_details_cache: dict[
            str,
            dict[str, Any],
        ] = {}
        self._connectors_cache: list[dict[str, Any]] | None = None

    def _get_clusters(self) -> list[dict[str, Any]]:
        if self._clusters_cache is None:
            self._clusters_cache = self.service.list_clusters()

        return self._clusters_cache

    def _get_cluster_details(
        self,
        cluster_arn: str,
    ) -> dict[str, Any]:
        if cluster_arn not in self._cluster_details_cache:
            self._cluster_details_cache[cluster_arn] = (
                self.service.describe_cluster(cluster_arn)
            )

        return self._cluster_details_cache[cluster_arn]

    def _get_connectors(self) -> list[dict[str, Any]]:
        if self._connectors_cache is None:
            self._connectors_cache = self.service.list_connectors()

        return self._connectors_cache

    @staticmethod
    def _cluster_public_access_type(
        cluster: dict[str, Any],
    ) -> str | None:
        provisioned = cluster.get("Provisioned")

        if not isinstance(provisioned, dict):
            return None

        broker_info = provisioned.get(
            "BrokerNodeGroupInfo"
        )

        if not isinstance(broker_info, dict):
            return None

        connectivity = broker_info.get(
            "ConnectivityInfo"
        )

        if not isinstance(connectivity, dict):
            return None

        public_access = connectivity.get(
            "PublicAccess"
        )

        if not isinstance(public_access, dict):
            return None

        value = public_access.get("Type")

        return (
            value
            if isinstance(value, str)
            else None
        )

    @staticmethod
    def _cluster_unauthenticated(
        cluster: dict[str, Any],
    ) -> bool | None:
        client_auth = cluster.get(
            "ClientAuthentication"
        )

        if not isinstance(client_auth, dict):
            return None

        unauthenticated = client_auth.get(
            "Unauthenticated"
        )

        if not isinstance(unauthenticated, dict):
            return None

        value = unauthenticated.get(
            "Enabled"
        )

        return (
            value
            if isinstance(value, bool)
            else None
        )

    @staticmethod
    def _cluster_in_cluster_encryption(
        cluster: dict[str, Any],
    ) -> bool | None:
        encryption_info = cluster.get(
            "EncryptionInfo"
        )

        if not isinstance(encryption_info, dict):
            return None

        encryption_in_transit = encryption_info.get(
            "EncryptionInTransit"
        )

        if not isinstance(encryption_in_transit, dict):
            return None

        value = encryption_in_transit.get(
            "InCluster"
        )

        return (
            value
            if isinstance(value, bool)
            else None
        )

    @staticmethod
    def _cluster_monitoring(
        cluster: dict[str, Any],
    ) -> str | None:
        value = cluster.get(
            "EnhancedMonitoring"
        )

        return (
            value
            if isinstance(value, str)
            else None
        )

    @staticmethod
    def _connector_logging_enabled(
        connector: dict[str, Any],
    ) -> bool:
        log_delivery = connector.get(
            "logDelivery"
        )

        if not isinstance(log_delivery, dict):
            return False

        worker_log_delivery = log_delivery.get(
            "workerLogDelivery"
        )

        if not isinstance(worker_log_delivery, dict):
            return False

        for destination in (
            "cloudWatchLogs",
            "firehose",
            "s3",
        ):
            config = worker_log_delivery.get(
                destination
            )

            if not isinstance(config, dict):
                continue

            if config.get("enabled") is True:
                return True

        return False

    def collect_clusters(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for summary in self._get_clusters():
            cluster_arn = summary.get(
                "ClusterArn"
            )

            if (
                not isinstance(cluster_arn, str)
                or not cluster_arn
            ):
                continue

            cluster = self._get_cluster_details(
                cluster_arn
            )

            cluster_type = cluster.get(
                "ClusterType"
            )

            if not isinstance(cluster_type, str):
                cluster_type = None

            normalized.append(
                {
                    "resource_id": cluster_arn,
                    "resource_type": "msk_cluster",
                    "resource_arn": cluster_arn,
                    "name": cluster.get(
                        "ClusterName"
                    ),
                    "cluster_type": cluster_type,
                    "state": cluster.get(
                        "State"
                    ),
                    "in_cluster_encryption": (
                        self._cluster_in_cluster_encryption(
                            cluster
                        )
                    ),
                    "enhanced_monitoring": (
                        self._cluster_monitoring(
                            cluster
                        )
                    ),
                    "public_access_type": (
                        self._cluster_public_access_type(
                            cluster
                        )
                    ),
                    "unauthenticated_access": (
                        self._cluster_unauthenticated(
                            cluster
                        )
                    ),
                }
            )

        return normalized

    def collect_connectors(self) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []

        for connector in self._get_connectors():
            connector_arn = connector.get(
                "connectorArn"
            )

            if (
                not isinstance(connector_arn, str)
                or not connector_arn
            ):
                continue

            encryption = connector.get(
                "kafkaClusterEncryptionInTransit"
            )

            if not isinstance(encryption, dict):
                encryption = {}

            encryption_type = encryption.get(
                "encryptionType"
            )

            if not isinstance(encryption_type, str):
                encryption_type = None

            normalized.append(
                {
                    "resource_id": connector_arn,
                    "resource_type": "msk_connector",
                    "resource_arn": connector_arn,
                    "name": connector.get(
                        "connectorName"
                    ),
                    "state": connector.get(
                        "connectorState"
                    ),
                    "encryption_type": encryption_type,
                    "logging_enabled": (
                        self._connector_logging_enabled(
                            connector
                        )
                    ),
                }
            )

        return normalized
