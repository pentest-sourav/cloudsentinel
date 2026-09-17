from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.app.models.scan import Scan


def create_scan(db: Session, provider: str) -> Scan:
    scan = Scan(
        provider=provider,
        status="pending",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def start_scan(db: Session, scan: Scan) -> Scan:
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    return scan


def complete_scan(db: Session, scan: Scan) -> Scan:
    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    return scan


def fail_scan(
    db: Session,
    scan: Scan,
    error_message: str,
) -> Scan:
    scan.status = "failed"
    scan.error_message = error_message
    scan.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    return scan
