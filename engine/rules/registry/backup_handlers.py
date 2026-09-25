from typing import Any

from scanner.aws.collectors.backup import (
    BackupDataCollector,
)


def collect_backup_vaults(
    collector: BackupDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_vaults()


def collect_backup_recovery_points(
    collector: BackupDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_recovery_points()


def collect_backup_plans(
    collector: BackupDataCollector,
) -> list[dict[str, Any]]:
    return collector.collect_backup_plans()


BACKUP_DATA_SOURCE_HANDLERS = {
    "backup_vaults": collect_backup_vaults,
    "backup_recovery_points": (
        collect_backup_recovery_points
    ),
    "backup_plans": collect_backup_plans,
}
