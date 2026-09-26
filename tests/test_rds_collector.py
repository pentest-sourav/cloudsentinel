from unittest.mock import MagicMock

from scanner.aws.collectors.rds import RDSDataCollector


def test_collect_instances_normalizes_rds_data():
    service = MagicMock()

    service.list_tags_for_resource.return_value = []

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "cloudsentinel-db",
            "DBInstanceArn": (
                "arn:aws:rds:us-east-1:123456789012:"
                "db:cloudsentinel-db"
            ),
            "Engine": "postgres",
            "EngineVersion": "16.3",
            "PubliclyAccessible": True,
            "StorageEncrypted": True,
            "BackupRetentionPeriod": 7,
            "MultiAZ": True,
            "DeletionProtection": True,
            "AutoMinorVersionUpgrade": True,
            "IAMDatabaseAuthenticationEnabled": True,
            "EnabledCloudwatchLogsExports": [
                "postgresql",
            ],
            "StorageType": "gp3",
            "AllocatedStorage": 100,
            "MonitoringInterval": 30,
            "DbInstancePort": 5432,
            "MasterUsername": "postgres",
            "DBClusterIdentifier": "cloudsentinel-cluster",
            "DBName": "cloudsentinel",
            "DBInstanceClass": "db.t3.medium",
            "DBInstanceStatus": "available",
            "KmsKeyId": (
                "arn:aws:kms:us-east-1:123456789012:key/example"
            ),
            "PreferredBackupWindow": "03:00-03:30",
            "AvailabilityZone": "us-east-1a",
            "DBSubnetGroup": {
                "DBSubnetGroupName": "default",
            },
            "VpcSecurityGroups": [
                {"VpcSecurityGroupId": "sg-12345678"}
            ],
            "CopyTagsToSnapshot": True,
            "CACertificateIdentifier": "rds-ca-rsa2048-g1",
            "PreferredMaintenanceWindow": "sun:04:00-sun:04:30",
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
            "auto_minor_version_upgrade": True,
            "iam_database_authentication_enabled": True,
            "enabled_cloudwatch_logs_exports": [
                "postgresql",
            ],
            "storage_type": "gp3",
            "allocated_storage": 100,
            "monitoring_interval": 30,
            "port": 5432,
            "admin_username": "postgres",
            "db_cluster_identifier": "cloudsentinel-cluster",
            "db_instance_arn": (
                "arn:aws:rds:us-east-1:123456789012:"
                "db:cloudsentinel-db"
            ),
            "db_name": "cloudsentinel",
            "db_instance_class": "db.t3.medium",
            "db_instance_status": "available",
            "kms_key_id": (
                "arn:aws:kms:us-east-1:123456789012:key/example"
            ),
            "preferred_backup_window": "03:00-03:30",
            "availability_zone": "us-east-1a",
            "db_subnet_group": {
                "DBSubnetGroupName": "default",
            },
            "vpc_security_groups": [
                {"VpcSecurityGroupId": "sg-12345678"}
            ],
            "copy_tags_to_snapshot": True,
            "ca_certificate_identifier": "rds-ca-rsa2048-g1",
            "preferred_maintenance_window": "sun:04:00-sun:04:30",
            "tags": [],
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


def test_collect_instances_preserves_unknown_optional_security_fields():
    service = MagicMock()

    service.describe_db_instances.return_value = [
        {
            "DBInstanceIdentifier": "cloudsentinel-db",
            "Engine": "postgres",
        }
    ]

    collector = RDSDataCollector(service)

    result = collector.collect_instances()

    assert result == [
        {
            "db_instance_id": "cloudsentinel-db",
            "db_instance_arn": None,
            "engine": "postgres",
            "engine_version": None,
            "db_name": None,
            "db_instance_class": None,
            "db_instance_status": None,
            "publicly_accessible": None,
            "storage_encrypted": None,
            "kms_key_id": None,
            "backup_retention_period": None,
            "preferred_backup_window": None,
            "multi_az": None,
            "availability_zone": None,
            "deletion_protection": None,
            "auto_minor_version_upgrade": None,
            "iam_database_authentication_enabled": None,
            "enabled_cloudwatch_logs_exports": None,
            "storage_type": None,
            "allocated_storage": None,
            "monitoring_interval": None,
            "port": None,
            "admin_username": None,
            "db_cluster_identifier": None,
            "db_subnet_group": None,
            "vpc_security_groups": None,
            "copy_tags_to_snapshot": None,
            "ca_certificate_identifier": None,
            "preferred_maintenance_window": None,
            "tags": None,
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
