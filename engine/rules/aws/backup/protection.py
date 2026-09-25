from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class BackupEncryptionResult:
    resource_id: str
    encryption_key_arn: str | None
    encryption_key_type: str | None
    status: str | None


@dataclass(frozen=True)
class BackupPlanSelectionResult:
    resource_id: str
    plan_name: str | None
    selection_count: int
    rules_count: int
    selections: list[dict[str, Any]]


@dataclass(frozen=True)
class BackupPlanLifecycleResult:
    resource_id: str
    plan_name: str | None
    rules: list[dict[str, Any]]
    has_valid_frequency: bool
    has_valid_retention: bool
    minimum_frequency_hours: int
    minimum_retention_days: int


@dataclass(frozen=True)
class BackupVaultLockResult:
    resource_id: str
    locked: bool | None
    lock_date: Any
    min_retention_days: int | None
    max_retention_days: int | None
    vault_state: str | None


def check_backup_recovery_point_encryption(
    resource_id: str,
    encryption_key_arn: str | None,
    encryption_key_type: str | None,
    status: str | None,
) -> BackupEncryptionResult | None:
    if not resource_id:
        return None

    normalized_status = (
        status.upper()
        if isinstance(status, str)
        else None
    )

    if normalized_status == "EXPIRED":
        return None

    if (
        isinstance(encryption_key_arn, str)
        and encryption_key_arn
    ):
        return None

    return BackupEncryptionResult(
        resource_id=resource_id,
        encryption_key_arn=encryption_key_arn,
        encryption_key_type=encryption_key_type,
        status=status,
    )


def check_backup_plan_selection(
    resource_id: str,
    plan_name: str | None,
    selection_count: int,
    rules_count: int,
    selections: list[dict[str, Any]],
) -> BackupPlanSelectionResult | None:
    if not resource_id:
        return None

    if rules_count <= 0:
        return BackupPlanSelectionResult(
            resource_id=resource_id,
            plan_name=plan_name,
            selection_count=selection_count,
            rules_count=rules_count,
            selections=selections,
        )

    if selection_count > 0:
        return None

    return BackupPlanSelectionResult(
        resource_id=resource_id,
        plan_name=plan_name,
        selection_count=selection_count,
        rules_count=rules_count,
        selections=selections,
    )


def _extract_delete_after_days(
    lifecycle: Any,
) -> int | None:
    if not isinstance(lifecycle, dict):
        return None

    value = lifecycle.get("DeleteAfterDays")

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    return None


def _schedule_is_at_most_daily(
    schedule_expression: Any,
) -> bool:
    if not isinstance(schedule_expression, str):
        return False

    expression = schedule_expression.strip().lower()

    if not expression:
        return False

    if expression.startswith("rate("):
        inside = expression[5:-1].strip()

        parts = inside.split()

        if len(parts) != 2:
            return False

        try:
            value = int(parts[0])
        except ValueError:
            return False

        unit = parts[1]

        if value <= 0:
            return False

        if unit.startswith("hour"):
            return value <= 24

        if unit.startswith("day"):
            return value <= 1

        return False

    if expression.startswith("cron("):
        # AWS Backup cron expressions are more expressive than
        # a simple parser can safely normalize. A cron expression
        # is therefore considered configured, but its exact
        # interval is not guessed here.
        return True

    return False


def check_backup_plan_frequency_retention(
    resource_id: str,
    plan_name: str | None,
    rules: list[dict[str, Any]],
    minimum_frequency_hours: int = 24,
    minimum_retention_days: int = 35,
) -> BackupPlanLifecycleResult | None:
    if not resource_id:
        return None

    valid_frequency = False
    valid_retention = False

    normalized_rules = [
        rule
        for rule in rules
        if isinstance(rule, dict)
    ]

    for rule in normalized_rules:
        schedule = rule.get(
            "ScheduleExpression"
        )

        lifecycle = rule.get(
            "Lifecycle",
            {},
        )

        retention_days = _extract_delete_after_days(
            lifecycle
        )

        frequency_ok = _schedule_is_at_most_daily(
            schedule
        )

        retention_ok = (
            retention_days is not None
            and retention_days >= minimum_retention_days
        )

        if frequency_ok:
            valid_frequency = True

        if retention_ok:
            valid_retention = True

        if frequency_ok and retention_ok:
            return None

    return BackupPlanLifecycleResult(
        resource_id=resource_id,
        plan_name=plan_name,
        rules=normalized_rules,
        has_valid_frequency=valid_frequency,
        has_valid_retention=valid_retention,
        minimum_frequency_hours=minimum_frequency_hours,
        minimum_retention_days=minimum_retention_days,
    )


def check_backup_vault_lock(
    resource_id: str,
    locked: bool | None,
    lock_date: Any,
    min_retention_days: int | None,
    max_retention_days: int | None,
    vault_state: str | None,
) -> BackupVaultLockResult | None:
    if not resource_id:
        return None

    if locked is True:
        return None

    return BackupVaultLockResult(
        resource_id=resource_id,
        locked=locked,
        lock_date=lock_date,
        min_retention_days=min_retention_days,
        max_retention_days=max_retention_days,
        vault_state=vault_state,
    )
