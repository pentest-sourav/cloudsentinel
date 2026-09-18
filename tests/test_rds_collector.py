from unittest.mock import MagicMock

from scanner.aws.collectors.rds import RDSDataCollector


def test_collect_instances_normalizes_rds_data():
    service = MagicMock()

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "cloudsentinel-db",
            "Engine": "postgres",
            "EngineVersion": "16.3",
            "PubliclyAccessible": True,
            "StorageEncrypted": True,
            "BackupRetentionPeriod": 7,
            "MultiAZ": True,
            "DeletionProtection": True,
            "StorageType": "gp3",
            "AllocatedStorage": 100,
        }
    ]

    collector = RDSDataCollector(service)

    result = collector.collect_instances()

    assert result == [
        {
            "db_instance_id": "cloudsentinel-db",
            "engine": "postgres",
            "engine_version": "16.3",
            "publicly_accessible": True,
            "storage_encrypted": True,
            "backup_retention_period": 7,
            "multi_az": True,
            "deletion_protection": True,
            "storage_type": "gp3",
            "allocated_storage": 100,
        }
    ]


def test_collect_instances_skips_instances_without_identifier():
    service = MagicMock()

    service.describe_db_instances.return_value = [
        {
            "Engine": "postgres",
            "StorageEncrypted": True,
        }
    ]

    collector = RDSDataCollector(service)

    result = collector.collect_instances()

    assert result == []


def test_collect_instances_uses_safe_defaults():
    service = MagicMock()

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "cloudsentinel-db",
        }
    ]

    collector = RDSDataCollector(service)

    result = collector.collect_instances()

    assert result == [
        {
            "db_instance_id": "cloudsentinel-db",
            "engine": None,
            "engine_version": None,
            "publicly_accessible": False,
            "storage_encrypted": False,
            "backup_retention_period": 0,
            "multi_az": False,
            "deletion_protection": False,
            "storage_type": None,
            "allocated_storage": None,
        }
    ]


def test_collect_instances_is_cached():
    service = MagicMock()

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "cloudsentinel-db",
        }
    ]

    collector = RDSDataCollector(service)

    first_result = collector.collect_instances()
    second_result = collector.collect_instances()

    assert first_result == second_result
    service.describe_db_instances.assert_called_once()
