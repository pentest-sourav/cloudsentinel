from unittest.mock import MagicMock

from scanner.aws.services.backup import BackupService


def test_list_backup_vaults_returns_vaults():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.list_backup_vaults.return_value = {
        "BackupVaultList": [
            {
                "BackupVaultName": "cloudsentinel-vault",
                "BackupVaultArn": (
                    "arn:aws:backup:us-east-1:123456789012:"
                    "backup-vault:cloudsentinel-vault"
                ),
            }
        ]
    }

    result = service.list_backup_vaults()

    assert len(result) == 1
    assert result[0]["BackupVaultName"] == "cloudsentinel-vault"

    service.backup_client.list_backup_vaults.assert_called_once_with(
        MaxResults=1000
    )


def test_list_backup_vaults_handles_multiple_pages():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.list_backup_vaults.side_effect = [
        {
            "BackupVaultList": [
                {"BackupVaultName": "vault-1"}
            ],
            "NextToken": "page-2",
        },
        {
            "BackupVaultList": [
                {"BackupVaultName": "vault-2"}
            ]
        },
    ]

    result = service.list_backup_vaults()

    assert [vault["BackupVaultName"] for vault in result] == [
        "vault-1",
        "vault-2",
    ]

    assert service.backup_client.list_backup_vaults.call_count == 2
    service.backup_client.list_backup_vaults.assert_any_call(
        MaxResults=1000
    )
    service.backup_client.list_backup_vaults.assert_any_call(
        MaxResults=1000,
        NextToken="page-2",
    )


def test_list_backup_vaults_handles_empty_response():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.list_backup_vaults.return_value = {
        "BackupVaultList": []
    }

    assert service.list_backup_vaults() == []


def test_describe_backup_vault_returns_details():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.describe_backup_vault.return_value = {
        "BackupVaultName": "cloudsentinel-vault",
        "Locked": True,
        "LockDate": 1760000000,
        "EncryptionKeyArn": (
            "arn:aws:kms:us-east-1:123456789012:key/test"
        ),
    }

    result = service.describe_backup_vault("cloudsentinel-vault")

    assert result["BackupVaultName"] == "cloudsentinel-vault"
    assert result["Locked"] is True

    service.backup_client.describe_backup_vault.assert_called_once_with(
        BackupVaultName="cloudsentinel-vault"
    )


def test_list_recovery_points_returns_points():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.list_recovery_points_by_backup_vault.return_value = {
        "RecoveryPoints": [
            {
                "RecoveryPointArn": (
                    "arn:aws:backup:us-east-1:123456789012:"
                    "recovery-point:test"
                ),
                "Status": "COMPLETED",
            }
        ]
    }

    result = service.list_recovery_points("cloudsentinel-vault")

    assert len(result) == 1
    assert result[0]["Status"] == "COMPLETED"

    service.backup_client.list_recovery_points_by_backup_vault.assert_called_once_with(
        BackupVaultName="cloudsentinel-vault",
        MaxResults=1000,
    )


def test_list_backup_plans_returns_plans():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.list_backup_plans.return_value = {
        "BackupPlansList": [
            {
                "BackupPlanId": "plan-123",
                "BackupPlanName": "daily-backups",
            }
        ]
    }

    result = service.list_backup_plans()

    assert len(result) == 1
    assert result[0]["BackupPlanId"] == "plan-123"

    service.backup_client.list_backup_plans.assert_called_once_with(
        MaxResults=1000
    )


def test_get_backup_plan_returns_plan_details():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.get_backup_plan.return_value = {
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

    result = service.get_backup_plan("plan-123")

    assert result["BackupPlanId"] == "plan-123"
    assert (
        result["BackupPlan"]["Rules"][0]["Lifecycle"]["DeleteAfterDays"]
        == 35
    )

    service.backup_client.get_backup_plan.assert_called_once_with(
        BackupPlanId="plan-123"
    )


def test_list_backup_selections_returns_selections():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.list_backup_selections.return_value = {
        "BackupSelectionsList": [
            {
                "SelectionId": "selection-123",
                "SelectionName": "production-resources",
                "BackupPlanId": "plan-123",
            }
        ]
    }

    result = service.list_backup_selections("plan-123")

    assert len(result) == 1
    assert result[0]["SelectionId"] == "selection-123"

    service.backup_client.list_backup_selections.assert_called_once_with(
        BackupPlanId="plan-123",
        MaxResults=1000,
    )


def test_list_report_plans_returns_report_plans():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.list_report_plans.return_value = {
        "ReportPlans": [
            {
                "ReportPlanName": "daily-report",
                "ReportPlanArn": (
                    "arn:aws:backup:us-east-1:123456789012:"
                    "report-plan:daily-report"
                ),
            }
        ]
    }

    result = service.list_report_plans()

    assert len(result) == 1
    assert result[0]["ReportPlanName"] == "daily-report"

    service.backup_client.list_report_plans.assert_called_once_with(
        MaxResults=1000
    )


def test_list_tags_returns_tag_map():
    service = BackupService.__new__(BackupService)
    service.backup_client = MagicMock()

    service.backup_client.list_tags.return_value = {
        "Tags": {
            "Environment": "production",
            "Owner": "security",
        }
    }

    result = service.list_tags(
        "arn:aws:backup:us-east-1:123456789012:"
        "backup-vault:cloudsentinel"
    )

    assert result == {
        "Environment": "production",
        "Owner": "security",
    }

    service.backup_client.list_tags.assert_called_once_with(
        ResourceArn=(
            "arn:aws:backup:us-east-1:123456789012:"
            "backup-vault:cloudsentinel"
        )
    )
