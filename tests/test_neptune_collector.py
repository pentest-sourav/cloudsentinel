from unittest.mock import Mock

from scanner.aws.collectors.neptune import NeptuneDataCollector


def make_service():
    service = Mock()

    service.describe_db_clusters.return_value = [
        {
            "DBClusterIdentifier": "cluster-1",
            "DBClusterArn": "arn:cluster-1",
            "StorageEncrypted": True,
            "EnabledCloudwatchLogsExports": ["audit"],
            "DeletionProtection": True,
            "BackupRetentionPeriod": 7,
            "IAMDatabaseAuthenticationEnabled": True,
        },
        {
            "DBClusterIdentifier": "cluster-2",
            "StorageEncrypted": False,
            "EnabledCloudwatchLogsExports": [],
            "DeletionProtection": False,
            "BackupRetentionPeriod": 1,
            "IAMDatabaseAuthenticationEnabled": False,
        },
    ]

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "instance-1",
            "DBClusterIdentifier": "cluster-1",
            "AvailabilityZone": "ap-south-1a",
        },
        {
            "DBInstanceIdentifier": "instance-2",
            "DBClusterIdentifier": "cluster-1",
            "AvailabilityZone": "ap-south-1b",
        },
        {
            "DBInstanceIdentifier": "instance-3",
            "DBClusterIdentifier": "cluster-2",
            "AvailabilityZone": "ap-south-1a",
        },
    ]

    service.describe_db_cluster_snapshots.return_value = [
        {
            "DBClusterSnapshotIdentifier": "manual-public",
            "DBClusterIdentifier": "cluster-1",
            "SnapshotType": "manual",
            "StorageEncrypted": True,
        },
        {
            "DBClusterSnapshotIdentifier": "automated-unencrypted",
            "DBClusterIdentifier": "cluster-2",
            "SnapshotType": "automated",
            "StorageEncrypted": False,
        },
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

    return service


def test_collect_clusters_normalizes_security_fields():
    collector = NeptuneDataCollector(make_service())

    result = collector.collect_clusters()

    assert result[0]["db_cluster_id"] == "cluster-1"
    assert result[0]["storage_encrypted"] is True
    assert result[0]["deletion_protection"] is True
    assert result[0]["backup_retention_period"] == 7
    assert result[0][
        "iam_database_authentication_enabled"
    ] is True
    assert result[0]["availability_zones"] == [
        "ap-south-1a",
        "ap-south-1b",
    ]
    assert result[0]["availability_zone_count"] == 2


def test_collect_clusters_preserves_missing_optional_values():
    service = Mock()
    service.describe_db_clusters.return_value = [
        {
            "DBClusterIdentifier": "cluster-1",
        }
    ]
    service.describe_db_instances.return_value = []

    collector = NeptuneDataCollector(service)

    result = collector.collect_clusters()

    assert result[0]["storage_encrypted"] is None
    assert result[0]["deletion_protection"] is None
    assert result[0]["backup_retention_period"] is None
    assert result[0][
        "iam_database_authentication_enabled"
    ] is None
    assert result[0]["availability_zone_count"] == 0


def test_collect_snapshots_checks_public_attribute_for_manual_snapshot():
    collector = NeptuneDataCollector(make_service())

    result = collector.collect_snapshots()

    public_snapshot = next(
        item
        for item in result
        if item["db_cluster_snapshot_id"] == "manual-public"
    )

    automated_snapshot = next(
        item
        for item in result
        if item["db_cluster_snapshot_id"]
        == "automated-unencrypted"
    )

    assert public_snapshot["is_public"] is True
    assert public_snapshot["storage_encrypted"] is True

    assert automated_snapshot["is_public"] is False
    assert automated_snapshot["storage_encrypted"] is False


def test_snapshot_attributes_are_cached():
    service = make_service()
    collector = NeptuneDataCollector(service)

    collector.collect_snapshots()
    collector.collect_snapshots()

    service.describe_db_cluster_snapshot_attributes.assert_called_once_with(
        "manual-public"
    )
