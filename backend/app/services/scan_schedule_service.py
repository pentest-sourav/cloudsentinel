from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.app.models.cloud_account import CloudAccount
from backend.app.models.scan_schedule import ScanSchedule
from backend.app.services.cloud_account_service import SCAN_ELIGIBLE_ACCOUNT_STATUSES

MIN_INTERVAL_MINUTES = 15
MAX_INTERVAL_MINUTES = 10080


def create_schedule(db: Session, *, tenant_id: int, cloud_account_id: int, interval_minutes: int) -> ScanSchedule:
    if not MIN_INTERVAL_MINUTES <= interval_minutes <= MAX_INTERVAL_MINUTES:
        raise ValueError(f"Schedule interval must be between {MIN_INTERVAL_MINUTES} and {MAX_INTERVAL_MINUTES} minutes.")
    account = db.query(CloudAccount).filter(
        CloudAccount.id == cloud_account_id,
        CloudAccount.tenant_id == tenant_id,
    ).first()
    if account is None:
        raise ValueError("Cloud account not found.")
    if account.provider != "aws":
        raise ValueError("Only AWS schedules are currently supported.")
    if account.status not in SCAN_ELIGIBLE_ACCOUNT_STATUSES:
        raise ValueError("Cloud account is not connected.")
    now = datetime.now(timezone.utc)
    schedule = ScanSchedule(
        tenant_id=tenant_id,
        cloud_account_id=cloud_account_id,
        provider=account.provider,
        interval_minutes=interval_minutes,
        enabled=True,
        next_run_at=now + timedelta(minutes=interval_minutes),
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule


def list_schedules(db: Session, tenant_id: int) -> list[ScanSchedule]:
    return db.query(ScanSchedule).filter(
        ScanSchedule.tenant_id == tenant_id,
    ).order_by(ScanSchedule.id.asc()).all()


def get_schedule(db: Session, schedule_id: int, tenant_id: int) -> ScanSchedule | None:
    return db.query(ScanSchedule).filter(
        ScanSchedule.id == schedule_id,
        ScanSchedule.tenant_id == tenant_id,
    ).first()


def set_schedule_enabled(db: Session, schedule: ScanSchedule, enabled: bool) -> ScanSchedule:
    schedule.enabled = enabled
    if enabled:
        schedule.next_run_at = datetime.now(timezone.utc) + timedelta(minutes=schedule.interval_minutes)
    db.commit()
    db.refresh(schedule)
    return schedule


def delete_schedule(db: Session, schedule: ScanSchedule) -> None:
    db.delete(schedule)
    db.commit()


def claim_due_schedules(db: Session, limit: int = 20) -> list[ScanSchedule]:
    now = datetime.now(timezone.utc)
    schedules = db.query(ScanSchedule).filter(
        ScanSchedule.enabled.is_(True),
        ScanSchedule.next_run_at <= now,
    ).order_by(ScanSchedule.next_run_at.asc()).with_for_update(skip_locked=True).limit(limit).all()
    for schedule in schedules:
        # Advance immediately inside the same transaction. If multiple workers
        # poll at once, row locking makes each due schedule claimable once.
        schedule.last_run_at = now
        schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
    if schedules:
        db.commit()
        for schedule in schedules:
            db.refresh(schedule)
    return schedules
