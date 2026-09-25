from unittest.mock import MagicMock

from scanner.aws.collectors.backup import BackupDataCollector


def test_collect_vaults_normalizes_vault_details():
    service = MagicMock()

    service.list_backup_vaults.return_value = [
        {
            "BackupVaultName": "cloudsentinel-vault",
            "BackupVaultArn": (
                "arn:aws:backup:us-east-1:123456789012:"
                "backup-vault:cloudsentinel-vault"
            ),
        }
    ]

    service.describe_backup_vault.return_value = {
        "BackupVaultName": "cloudsentinel-vault",
        "BackupVaultArn": (
            "arn:aws:backup:us-east-1:123456789012:"
            "backup-vault:cloudsentinel-vault"
        ),
        "VaultState": "AVAILABLE",
        "VaultType": "BACKUP_VAULT",
        "Locked": True,
        "LockDate": 1760000000,
        "MinRetentionDays": 35,
        "MaxRetentionDays": 365,
        "EncryptionKeyArn": (
            "arn:aws:kms:us-east-1:123456789012:key/test"
        ),
        "EncryptionKeyType": "KMS",
        "NumberOfRecoveryPoints": 10,
    }

    collector = BackupDataCollector(service)

    result = collector.collect_vaults()

    assert result == [
        {
            "resource_id": "cloudsentinel-vault",
            "resource_type": "backup_vault",
            "resource_arn": (
                "arn:aws:backup:us-east-1:123456789012:"
                "backup-vault:cloudsentinel-vault"
            ),
            "vault_state": "AVAILABLE",
            "vault_type": "BACKUP_VAULT",
            "locked": True,
            "lock_date": 1760000000,
            "min_retention_days": 35,
            "max_retention_days": 365,
            "encryption_key_arn": (
                "arn:aws:kms:us-east-1:123456789012:key/test"
            ),
            "encryption_key_type": "KMS",
            "number_of_recovery_points": 10,
        }
    ]


def test_collect_recovery_points_normalizes_encryption_fields():
    service = MagicMock()

    service.list_backup_vaults.return_value = [
        {
            "BackupVaultName": "cloudsentinel-vault",
            "BackupVaultArn": (
                "arn:aws:backup:us-east-1:123456789012:"
                "backup-vault:cloudsentinel-vault"
            ),
        }
    ]

    service.list_recovery_points.return_value = [
        {
            "RecoveryPointArn": (
                "arn:aws:backup:us-east-1:123456789012:"
                "recovery-point:test"
            ),
            "Status": "COMPLETED",
            "EncryptionKeyArn": (
                "arn:aws:kms:us-east-1:123456789012:key/test"
            ),
            "EncryptionKeyType": "KMS",
            "ResourceArn": (
                "arn:aws:rds:us-east-1:123456789012:db:test"
            ),
            "ResourceType": "RDS",
        }
    ]

    result = BackupDataCollector(service).collect_recovery_points()

    assert result == [
        {
            "resource_id": (
                "arn:aws:backup:us-east-1:123456789012:"
                "recovery-point:test"
            ),
            "resource_type": "backup_recovery_point",
            "resource_arn": (
                "arn:aws:backup:us-east-1:123456789012:"
                "recovery-point:test"
            ),
            "backup_vault_name": "cloudsentinel-vault",
            "encryption_key_arn": (
                "arn:aws:kms:us-east-1:123456789012:key/test"
            ),
            "encryption_key_type": "KMS",
            "status": "COMPLETED",
            "resource_arn_source": (
                "arn:aws:rds:us-east-1:123456789012:db:test"
            ),
            "resource_type_source": "RDS",
        }
    ]


def test_collect_backup_plans_includes_rules_and_selections():
    service = MagicMock()

    service.list_backup_plans.return_value = [
        {
            "BackupPlanId": "plan-123",
            "BackupPlanName": "daily-backups",
            "BackupPlanArn": (
                "arn:aws:backup:us-east-1:123456789012:"
                "plan:plan-123"
            ),
            "VersionId": "version-1",
        }
    ]

    service.get_backup_plan.return_value = {
        "BackupPlanId": "plan-123",
        "BackupPlan": {
            "BackupPlanName": "daily-backups",
            "Rules": [
                {
                    "RuleName": "daily",
                    "ScheduleExpression": "rate(1 day)",
                    "Lifecycle": {
                        "DeleteAfterDays": 35
                    },
                }
            ],
        },
        "VersionId": "version-1",
    }

    service.list_backup_selections.return_value = [
        {
            "SelectionId": "selection-123",
            "SelectionName": "production",
            "BackupPlanId": "plan-123",
        }
    ]

    result = BackupDataCollector(service).collect_backup_plans()

    assert len(result) == 1
    assert result[0]["resource_id"] == "plan-123"
    assert result[0]["resource_type"] == "backup_plan"
    assert result[0]["plan_name"] == "daily-backups"
    assert result[0]["rules_count"] == 1
    assert result[0]["rules"][0]["ScheduleExpression"] == "rate(1 day)"
    assert result[0]["selection_count"] == 1
    assert result[0]["selections"][0]["SelectionId"] == "selection-123"
    assert result[0]["version_id"] == "version-1"


def test_collect_vaults_is_cached():
    service = MagicMock()

    service.list_backup_vaults.return_value = [
        {
            "BackupVaultName": "cloudsentinel-vault",
            "BackupVaultArn": (
                "arn:aws:backup:us-east-1:123456789012:"
                "backup-vault:cloudsentinel-vault"
            ),
        }
    ]

    service.describe_backup_vault.return_value = {
        "VaultState": "AVAILABLE",
        "VaultType": "BACKUP_VAULT",
        "Locked": True,
    }

    collector = BackupDataCollector(service)

    first = collector.collect_vaults()
    second = collector.collect_vaults()

    assert first == second
    service.list_backup_vaults.assert_called_once()
    service.describe_backup_vault.assert_called_once()


def test_collect_backup_plans_is_cached():
    service = MagicMock()

    service.list_backup_plans.return_value = [
        {
            "BackupPlanId": "plan-123",
            "BackupPlanName": "daily-backups",
            "BackupPlanArn": (
                "arn:aws:backup:us-east-1:123456789012:"
                "plan:plan-123"
            ),
        }
    ]

    service.get_backup_plan.return_value = {
        "BackupPlan": {
            "BackupPlanName": "daily-backups",
            "Rules": [],
        }
    }

    service.list_backup_selections.return_value = []

    collector = BackupDataCollector(service)

    first = collector.collect_backup_plans()
    second = collector.collect_backup_plans()

    assert first == second
    service.list_backup_plans.assert_called_once()
    service.get_backup_plan.assert_called_once()
    service.list_backup_selections.assert_called_once()
