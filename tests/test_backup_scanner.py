from unittest.mock import MagicMock

from scanner.aws.scanners.backup import BackupScanner


def test_backup_scanner_detects_unencrypted_recovery_point():
    service = MagicMock()

    service.list_backup_vaults.return_value = [
        {
            "BackupVaultName": "cloudsentinel-vault",
            "BackupVaultArn": "arn:aws:backup:us-east-1:123456789012:backup-vault:cloudsentinel-vault",
        }
    ]

    service.describe_backup_vault.return_value = {
        "VaultState": "AVAILABLE",
        "VaultType": "BACKUP_VAULT",
        "Locked": True,
    }

    service.list_recovery_points.return_value = [
        {
            "RecoveryPointArn": "recovery-point-1",
            "Status": "COMPLETED",
            "EncryptionKeyArn": None,
            "EncryptionKeyType": None,
            "ResourceArn": "arn:aws:rds:us-east-1:123456789012:db:test",
            "ResourceType": "RDS",
        }
    ]

    service.list_backup_plans.return_value = []
    service.list_tags.return_value = {"Tags": {}}

    scanner = BackupScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-BACKUP-001"
    assert finding.resource_id == "recovery-point-1"
    assert finding.severity.value == "medium"


def test_backup_scanner_detects_unlocked_vault():
    service = MagicMock()

    service.list_backup_vaults.return_value = [
        {
            "BackupVaultName": "cloudsentinel-vault",
            "BackupVaultArn": "arn:aws:backup:us-east-1:123456789012:backup-vault:cloudsentinel-vault",
        }
    ]

    service.describe_backup_vault.return_value = {
        "VaultState": "AVAILABLE",
        "VaultType": "BACKUP_VAULT",
        "Locked": False,
    }

    service.list_recovery_points.return_value = []
    service.list_backup_plans.return_value = []
    service.list_tags.return_value = {"Tags": {}}

    scanner = BackupScanner(service)

    findings = scanner.scan()

    assert len(findings) == 1

    finding = findings[0]

    assert finding.rule_id == "CS-AWS-BACKUP-004"
    assert finding.resource_id == "cloudsentinel-vault"
    assert finding.severity.value == "high"


def test_backup_scanner_returns_no_findings_for_compliant_backup_configuration():
    service = MagicMock()

    service.list_backup_vaults.return_value = [
        {
            "BackupVaultName": "cloudsentinel-vault",
            "BackupVaultArn": "arn:aws:backup:us-east-1:123456789012:backup-vault:cloudsentinel-vault",
        }
    ]

    service.describe_backup_vault.return_value = {
        "VaultState": "AVAILABLE",
        "VaultType": "BACKUP_VAULT",
        "Locked": True,
        "LockDate": 1760000000,
        "MinRetentionDays": 35,
        "MaxRetentionDays": 365,
    }

    service.list_recovery_points.return_value = [
        {
            "RecoveryPointArn": "recovery-point-1",
            "Status": "COMPLETED",
            "EncryptionKeyArn": "arn:aws:kms:us-east-1:123456789012:key/test",
            "EncryptionKeyType": "KMS",
            "ResourceArn": "arn:aws:rds:us-east-1:123456789012:db:test",
            "ResourceType": "RDS",
        }
    ]

    service.list_backup_plans.return_value = [
        {
            "BackupPlanId": "plan-123",
            "BackupPlanName": "daily-backups",
            "BackupPlanArn": "arn:aws:backup:us-east-1:123456789012:plan:plan-123",
            "VersionId": "version-1",
        }
    ]

    service.get_backup_plan.return_value = {
        "BackupPlan": {
            "BackupPlanName": "daily-backups",
            "Rules": [
                {
                    "RuleName": "daily",
                    "ScheduleExpression": "rate(1 day)",
                    "Lifecycle": {
                        "DeleteAfterDays": 35,
                    },
                }
            ],
        },
        "VersionId": "version-1",
    }

    service.list_backup_selections.return_value = [
        {
            "SelectionId": "selection-1",
            "SelectionName": "production",
        }
    ]

    service.list_tags.return_value = {"Tags": {}}

    scanner = BackupScanner(service)

    findings = scanner.scan()

    assert findings == []


def test_backup_scanner_handles_empty_account():
    service = MagicMock()

    service.list_backup_vaults.return_value = []
    service.list_backup_plans.return_value = []

    scanner = BackupScanner(service)

    findings = scanner.scan()

    assert findings == []
