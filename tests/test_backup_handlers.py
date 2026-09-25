from unittest.mock import MagicMock

from engine.rules.registry.backup_handlers import (
    BACKUP_DATA_SOURCE_HANDLERS,
    collect_backup_plans,
    collect_backup_recovery_points,
    collect_backup_vaults,
)


def test_collect_backup_vaults_calls_collector():
    collector = MagicMock()
    collector.collect_vaults.return_value = [
        {
            "resource_id": "cloudsentinel-vault",
            "locked": True,
        }
    ]

    result = collect_backup_vaults(collector)

    assert result == [
        {
            "resource_id": "cloudsentinel-vault",
            "locked": True,
        }
    ]

    collector.collect_vaults.assert_called_once()


def test_collect_backup_recovery_points_calls_collector():
    collector = MagicMock()
    collector.collect_recovery_points.return_value = [
        {
            "resource_id": "recovery-point-1",
            "status": "COMPLETED",
        }
    ]

    result = collect_backup_recovery_points(collector)

    assert result == [
        {
            "resource_id": "recovery-point-1",
            "status": "COMPLETED",
        }
    ]

    collector.collect_recovery_points.assert_called_once()


def test_collect_backup_plans_calls_collector():
    collector = MagicMock()
    collector.collect_backup_plans.return_value = [
        {
            "plan_id": "plan-123",
            "selection_count": 1,
        }
    ]

    result = collect_backup_plans(collector)

    assert result == [
        {
            "plan_id": "plan-123",
            "selection_count": 1,
        }
    ]

    collector.collect_backup_plans.assert_called_once()


def test_backup_data_source_handlers_are_registered():
    assert BACKUP_DATA_SOURCE_HANDLERS["backup_vaults"] is collect_backup_vaults
    assert (
        BACKUP_DATA_SOURCE_HANDLERS["backup_recovery_points"]
        is collect_backup_recovery_points
    )
    assert BACKUP_DATA_SOURCE_HANDLERS["backup_plans"] is collect_backup_plans
