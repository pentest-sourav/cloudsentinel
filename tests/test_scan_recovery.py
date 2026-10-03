from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from backend.app.services.scan_service import (
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    recover_stale_running_scan,
    touch_scan_heartbeat,
)


def _db_for(scan):
    db = MagicMock()
    (
        db.query.return_value
        .filter.return_value
        .with_for_update.return_value
        .one.return_value
    ) = scan
    return db


def test_recover_stale_running_scan_keeps_live_scan_running():
    scan = SimpleNamespace(
        id=42,
        status=SCAN_STATUS_RUNNING,
        updated_at=datetime.now(timezone.utc),
    )
    db = _db_for(scan)

    result = recover_stale_running_scan(
        db=db,
        scan=scan,
        stale_after_seconds=120,
    )

    assert result is scan
    assert scan.status == SCAN_STATUS_RUNNING
    db.commit.assert_not_called()


def test_recover_stale_running_scan_returns_stale_scan_to_pending():
    scan = SimpleNamespace(
        id=42,
        status=SCAN_STATUS_RUNNING,
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        started_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        completed_at=None,
        error_message=None,
    )
    db = _db_for(scan)

    result = recover_stale_running_scan(
        db=db,
        scan=scan,
        stale_after_seconds=120,
    )

    assert result is scan
    assert scan.status == SCAN_STATUS_PENDING
    assert scan.started_at is None
    assert scan.completed_at is None
    assert "worker stopped responding" in scan.error_message
    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(scan)


def test_touch_scan_heartbeat_only_updates_running_scan():
    db = MagicMock()
    db.query.return_value.filter.return_value.update.return_value = 1

    assert touch_scan_heartbeat(db=db, scan_id=42) is True

    db.commit.assert_called_once()
    db.query.return_value.filter.return_value.update.assert_called_once()


def test_touch_scan_heartbeat_reports_missing_or_finished_scan():
    db = MagicMock()
    db.query.return_value.filter.return_value.update.return_value = 0

    assert touch_scan_heartbeat(db=db, scan_id=42) is False

    db.commit.assert_called_once()
