from unittest.mock import Mock

from scanner.aws.collectors.msk import MSKDataCollector


def test_collect_clusters_normalizes_security_fields():
    service = Mock()

    service.list_clusters.return_value = [
        {
            "ClusterArn": "arn:cluster:1",
        },
    ]

    service.describe_cluster.return_value = {
        "ClusterArn": "arn:cluster:1",
        "ClusterName": "prod-msk",
        "ClusterType": "PROVISIONED",
        "State": "ACTIVE",
        "ClientAuthentication": {
            "Unauthenticated": {
                "Enabled": True,
            },
        },
        "EncryptionInfo": {
            "EncryptionInTransit": {
                "InCluster": False,
            },
        },
        "EnhancedMonitoring": "DEFAULT",
        "Provisioned": {
            "BrokerNodeGroupInfo": {
                "ConnectivityInfo": {
                    "PublicAccess": {
                        "Type": "SERVICE_PROVIDED_EIPS",
                    },
                },
            },
        },
    }

    collector = MSKDataCollector(service)

    assert collector.collect_clusters() == [
        {
            "resource_id": "arn:cluster:1",
            "resource_type": "msk_cluster",
            "resource_arn": "arn:cluster:1",
            "name": "prod-msk",
            "cluster_type": "PROVISIONED",
            "state": "ACTIVE",
            "in_cluster_encryption": False,
            "enhanced_monitoring": "DEFAULT",
            "public_access_type": "SERVICE_PROVIDED_EIPS",
            "unauthenticated_access": True,
        },
    ]


def test_collect_serverless_cluster_does_not_invent_provisioned_fields():
    service = Mock()

    service.list_clusters.return_value = [
        {
            "ClusterArn": "arn:serverless",
        },
    ]

    service.describe_cluster.return_value = {
        "ClusterArn": "arn:serverless",
        "ClusterName": "serverless",
        "ClusterType": "SERVERLESS",
        "State": "ACTIVE",
        "ClientAuthentication": {
            "Sasl": {
                "Iam": {
                    "Enabled": True,
                },
            },
        },
        "Serverless": {
            "ConnectivityInfo": {
                "NetworkType": "IPV4",
            },
        },
    }

    collector = MSKDataCollector(service)

    result = collector.collect_clusters()[0]

    assert result["cluster_type"] == "SERVERLESS"
    assert result["public_access_type"] is None
    assert result["enhanced_monitoring"] is None
    assert result["unauthenticated_access"] is None


def test_collect_connectors_normalizes_encryption_and_logging():
    service = Mock()

    service.list_connectors.return_value = [
        {
            "connectorArn": "arn:connector:1",
            "connectorName": "prod-connector",
            "connectorState": "RUNNING",
            "kafkaClusterEncryptionInTransit": {
                "encryptionType": "PLAINTEXT",
            },
            "logDelivery": {
                "workerLogDelivery": {
                    "cloudWatchLogs": {
                        "enabled": False,
                    },
                    "s3": {
                        "enabled": True,
                        "bucket": "logs",
                    },
                    "firehose": {
                        "enabled": False,
                    },
                },
            },
        },
    ]

    collector = MSKDataCollector(service)

    assert collector.collect_connectors() == [
        {
            "resource_id": "arn:connector:1",
            "resource_type": "msk_connector",
            "resource_arn": "arn:connector:1",
            "name": "prod-connector",
            "state": "RUNNING",
            "encryption_type": "PLAINTEXT",
            "logging_enabled": True,
        },
    ]


def test_collector_caches_cluster_and_connector_data():
    service = Mock()

    service.list_clusters.return_value = [
        {
            "ClusterArn": "arn:cluster:1",
        },
    ]

    service.describe_cluster.return_value = {
        "ClusterArn": "arn:cluster:1",
        "ClusterType": "PROVISIONED",
    }

    service.list_connectors.return_value = [
        {
            "connectorArn": "arn:connector:1",
        },
    ]

    collector = MSKDataCollector(service)

    collector.collect_clusters()
    collector.collect_clusters()
    collector.collect_connectors()
    collector.collect_connectors()

    service.list_clusters.assert_called_once()
    service.describe_cluster.assert_called_once_with(
        "arn:cluster:1"
    )
    service.list_connectors.assert_called_once()
