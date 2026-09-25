from engine.findings.model import Severity
from engine.rules.aws.backup.protection import (
    check_backup_plan_frequency_retention,
    check_backup_plan_selection,
    check_backup_recovery_point_encryption,
    check_backup_vault_lock,
)
from engine.rules.registry.backup_registry import (
    _build_encryption_finding,
    _build_lifecycle_finding,
    _build_selection_finding,
    _build_vault_lock_finding,
)


def test_unencrypted_backup_recovery_point_is_detected():
    result = check_backup_recovery_point_encryption(
        resource_id="recovery-point-1",
        encryption_key_arn=None,
        encryption_key_type=None,
        status="COMPLETED",
    )

    assert result is not None
    assert result.resource_id == "recovery-point-1"
    assert result.encryption_key_arn is None


def test_encrypted_backup_recovery_point_is_not_detected():
    result = check_backup_recovery_point_encryption(
        resource_id="recovery-point-1",
        encryption_key_arn=(
            "arn:aws:kms:us-east-1:123456789012:key/test"
        ),
        encryption_key_type="KMS",
        status="COMPLETED",
    )

    assert result is None


def test_expired_backup_recovery_point_is_ignored():
    result = check_backup_recovery_point_encryption(
        resource_id="recovery-point-1",
        encryption_key_arn=None,
        encryption_key_type=None,
        status="EXPIRED",
    )

    assert result is None


def test_missing_recovery_point_id_is_ignored():
    result = check_backup_recovery_point_encryption(
        resource_id="",
        encryption_key_arn=None,
        encryption_key_type=None,
        status="COMPLETED",
    )

    assert result is None


def test_backup_encryption_finding():
    result = check_backup_recovery_point_encryption(
        resource_id="recovery-point-1",
        encryption_key_arn=None,
        encryption_key_type=None,
        status="COMPLETED",
    )

    finding = _build_encryption_finding(result)

    assert finding.rule_id == "CS-AWS-BACKUP-001"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "backup_recovery_point"
    assert finding.resource_id == "recovery-point-1"
    assert finding.evidence["encrypted_at_rest"] is False


def test_backup_plan_without_selection_is_detected():
    result = check_backup_plan_selection(
        resource_id="plan-123",
        plan_name="daily-backups",
        selection_count=0,
        rules_count=1,
        selections=[],
    )

    assert result is not None
    assert result.resource_id == "plan-123"
    assert result.selection_count == 0
    assert result.rules_count == 1


def test_backup_plan_with_selection_is_not_detected():
    result = check_backup_plan_selection(
        resource_id="plan-123",
        plan_name="daily-backups",
        selection_count=1,
        rules_count=1,
        selections=[
            {
                "SelectionId": "selection-1",
                "SelectionName": "production",
            }
        ],
    )

    assert result is None


def test_backup_plan_without_rules_is_detected():
    result = check_backup_plan_selection(
        resource_id="plan-123",
        plan_name="daily-backups",
        selection_count=1,
        rules_count=0,
        selections=[
            {
                "SelectionId": "selection-1",
                "SelectionName": "production",
            }
        ],
    )

    assert result is not None
    assert result.rules_count == 0


def test_backup_plan_selection_finding():
    result = check_backup_plan_selection(
        resource_id="plan-123",
        plan_name="daily-backups",
        selection_count=0,
        rules_count=1,
        selections=[],
    )

    finding = _build_selection_finding(result)

    assert finding.rule_id == "CS-AWS-BACKUP-002"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "backup_plan"
    assert finding.resource_id == "plan-123"
    assert finding.evidence["selection_count"] == 0


def test_backup_plan_with_daily_frequency_and_35_day_retention_is_not_detected():
    result = check_backup_plan_frequency_retention(
        resource_id="plan-123",
        plan_name="daily-backups",
        rules=[
            {
                "ScheduleExpression": "rate(1 day)",
                "Lifecycle": {
                    "DeleteAfterDays": 35,
                },
            }
        ],
    )

    assert result is None


def test_backup_plan_with_short_retention_is_detected():
    result = check_backup_plan_frequency_retention(
        resource_id="plan-123",
        plan_name="daily-backups",
        rules=[
            {
                "ScheduleExpression": "rate(1 day)",
                "Lifecycle": {
                    "DeleteAfterDays": 7,
                },
            }
        ],
    )

    assert result is not None
    assert result.has_valid_frequency is True
    assert result.has_valid_retention is False
    assert result.minimum_frequency_hours == 24
    assert result.minimum_retention_days == 35


def test_backup_plan_with_slow_frequency_is_detected():
    result = check_backup_plan_frequency_retention(
        resource_id="plan-123",
        plan_name="weekly-backups",
        rules=[
            {
                "ScheduleExpression": "rate(7 days)",
                "Lifecycle": {
                    "DeleteAfterDays": 35,
                },
            }
        ],
    )

    assert result is not None
    assert result.has_valid_frequency is False
    assert result.has_valid_retention is True


def test_backup_plan_without_rules_is_detected_for_frequency_retention():
    result = check_backup_plan_frequency_retention(
        resource_id="plan-123",
        plan_name="empty-plan",
        rules=[],
    )

    assert result is not None
    assert result.has_valid_frequency is False
    assert result.has_valid_retention is False


def test_backup_plan_frequency_retention_finding():
    result = check_backup_plan_frequency_retention(
        resource_id="plan-123",
        plan_name="weekly-backups",
        rules=[
            {
                "ScheduleExpression": "rate(7 days)",
                "Lifecycle": {
                    "DeleteAfterDays": 35,
                },
            }
        ],
    )

    finding = _build_lifecycle_finding(result)

    assert finding.rule_id == "CS-AWS-BACKUP-003"
    assert finding.severity == Severity.MEDIUM
    assert finding.resource_type == "backup_plan"
    assert finding.resource_id == "plan-123"
    assert finding.evidence["has_valid_frequency"] is False
    assert finding.evidence["has_valid_retention"] is True


def test_unlocked_backup_vault_is_detected():
    result = check_backup_vault_lock(
        resource_id="cloudsentinel-vault",
        locked=False,
        lock_date=None,
        min_retention_days=None,
        max_retention_days=None,
        vault_state="AVAILABLE",
    )

    assert result is not None
    assert result.resource_id == "cloudsentinel-vault"
    assert result.locked is False


def test_locked_backup_vault_is_not_detected():
    result = check_backup_vault_lock(
        resource_id="cloudsentinel-vault",
        locked=True,
        lock_date=1760000000,
        min_retention_days=35,
        max_retention_days=365,
        vault_state="AVAILABLE",
    )

    assert result is None


def test_missing_backup_vault_id_is_ignored():
    result = check_backup_vault_lock(
        resource_id="",
        locked=False,
        lock_date=None,
        min_retention_days=None,
        max_retention_days=None,
        vault_state="AVAILABLE",
    )

    assert result is None


def test_backup_vault_lock_finding():
    result = check_backup_vault_lock(
        resource_id="cloudsentinel-vault",
        locked=False,
        lock_date=None,
        min_retention_days=None,
        max_retention_days=None,
        vault_state="AVAILABLE",
    )

    finding = _build_vault_lock_finding(result)

    assert finding.rule_id == "CS-AWS-BACKUP-004"
    assert finding.severity == Severity.HIGH
    assert finding.resource_type == "backup_vault"
    assert finding.resource_id == "cloudsentinel-vault"
    assert finding.evidence["locked"] is False
