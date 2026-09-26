from unittest.mock import Mock

from scanner.aws.collectors.documentdb import DocumentDBDataCollector


def test_collect_clusters_normalizes_security_relevant_fields():
    service = Mock()
    service.describe_db_clusters.return_value = [
        {
            "DBClusterIdentifier": "cluster-1",
            "DBClusterArn": "arn:aws:rds:region:account:cluster:cluster-1",
            "Engine": "docdb",
            "EngineVersion": "5.0.0",
            "StorageEncrypted": True,
            "KmsKeyId": "kms-key",
            "BackupRetentionPeriod": 7,
            "DeletionProtection": True,
            "EnabledCloudwatchLogsExports": ["audit", "profiler"],
            "DBClusterParameterGroup": [
                {
                    "DBClusterParameterGroupName": "custom-docdb",
                    "ParameterApplyStatus": "in-sync",
                }
            ],
        }
    ]
    service.describe_db_cluster_parameters.return_value = [
        {
            "ParameterName": "tls",
            "ParameterValue": "tls1.2+",
        }
    ]

    collector = DocumentDBDataCollector(service)
    result = collector.collect_clusters()

    assert result == [
        {
            "db_cluster_id": "cluster-1",
            "db_cluster_arn": (
                "arn:aws:rds:region:account:cluster:cluster-1"
            ),
            "engine": "docdb",
            "engine_version": "5.0.0",
            "status": None,
            "storage_encrypted": True,
            "kms_key_id": "kms-key",
            "backup_retention_period": 7,
            "deletion_protection": True,
            "enabled_cloudwatch_logs_exports": ["audit", "profiler"],
            "parameter_group_name": "custom-docdb",
            "parameter_apply_status": "in-sync",
            "tls_parameter": "tls1.2+",
            "tag_data_available": True,
        }
    ]


def test_collector_caches_cluster_parameters():
    service = Mock()
    service.describe_db_clusters.return_value = [
        {
            "DBClusterIdentifier": "cluster-1",
            "DBClusterParameterGroup": [
                {
                    "DBClusterParameterGroupName": "same-group",
                    "ParameterApplyStatus": "in-sync",
                }
            ],
        },
        {
            "DBClusterIdentifier": "cluster-2",
            "DBClusterParameterGroup": [
                {
                    "DBClusterParameterGroupName": "same-group",
                    "ParameterApplyStatus": "in-sync",
                }
            ],
        },
    ]
    service.describe_db_cluster_parameters.return_value = [
        {
            "ParameterName": "tls",
            "ParameterValue": "tls1.2+",
        }
    ]

    collector = DocumentDBDataCollector(service)

    result = collector.collect_clusters()

    assert len(result) == 2
    service.describe_db_cluster_parameters.assert_called_once_with(
        "same-group"
    )


def test_collect_snapshots_detects_public_restore_permission():
    service = Mock()
    service.describe_db_cluster_snapshots.return_value = [
        {
            "DBClusterSnapshotIdentifier": "snapshot-1",
            "DBClusterIdentifier": "cluster-1",
            "StorageEncrypted": True,
            "SnapshotType": "manual",
        }
    ]
    service.describe_db_cluster_snapshot_attributes.return_value = {
        "DBClusterSnapshotAttributesResult": {
            "DBClusterSnapshotAttributes": [
                {
                    "AttributeName": "restore",
                    "AttributeValues": ["all"],
                }
            ]
        }
    }

    collector = DocumentDBDataCollector(service)
    result = collector.collect_snapshots()

    assert result[0]["snapshot_id"] == "snapshot-1"
    assert result[0]["shared_accounts"] == ["all"]


def test_collect_snapshots_caches_attributes():
    service = Mock()
    service.describe_db_cluster_snapshots.return_value = [
        {
            "DBClusterSnapshotIdentifier": "snapshot-1",
            "SnapshotType": "manual",
        },
        {
            "DBClusterSnapshotIdentifier": "snapshot-1",
            "SnapshotType": "manual",
        },
    ]
    service.describe_db_cluster_snapshot_attributes.return_value = {
        "DBClusterSnapshotAttributesResult": {
            "DBClusterSnapshotAttributes": []
        }
    }

    collector = DocumentDBDataCollector(service)
    result = collector.collect_snapshots()

    assert len(result) == 2
    service.describe_db_cluster_snapshot_attributes.assert_called_once_with(
        "snapshot-1"
    )
