from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.services.scan_summary_service import (
    build_finding_counts,
)


SCAN_STATUS_PENDING = "pending"
SCAN_STATUS_RUNNING = "running"
SCAN_STATUS_COMPLETED = "completed"
SCAN_STATUS_FAILED = "failed"

VALID_SCAN_STATUSES = {
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
}


def create_scan(
    db: Session,
    provider: str,
) -> Scan:
    scan = Scan(
        provider=provider,
        status=SCAN_STATUS_PENDING,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def get_scan(
    db: Session,
    scan_id: int,
) -> Scan | None:
    return (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )


def start_scan(
    db: Session,
    scan: Scan,
) -> Scan:
    if scan.status != SCAN_STATUS_PENDING:
        raise ValueError(
            f"Cannot start scan {scan.id} from status "
            f"'{scan.status}'."
        )

    scan.status = SCAN_STATUS_RUNNING
    scan.started_at = datetime.now(timezone.utc)
    scan.error_message = None

    db.commit()
    db.refresh(scan)

    return scan


def complete_scan(
    db: Session,
    scan: Scan,
) -> Scan:
    if scan.status != SCAN_STATUS_RUNNING:
        raise ValueError(
            f"Cannot complete scan {scan.id} from status "
            f"'{scan.status}'."
        )

    scan.status = SCAN_STATUS_COMPLETED
    scan.completed_at = datetime.now(timezone.utc)
    scan.error_message = None

    db.commit()
    db.refresh(scan)

    return scan


def fail_scan(
    db: Session,
    scan: Scan,
    error_message: str,
) -> Scan:
    if scan.status not in {
        SCAN_STATUS_PENDING,
        SCAN_STATUS_RUNNING,
    }:
        raise ValueError(
            f"Cannot fail scan {scan.id} from status "
            f"'{scan.status}'."
        )

    scan.status = SCAN_STATUS_FAILED
    scan.error_message = error_message[:4000]
    scan.completed_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    return scan


def retry_scan(
    db: Session,
    scan: Scan,
) -> Scan:
    """
    Requeue a failed scan for another execution attempt.

    Retry orchestration is intentionally separate from start_scan()
    so normal scans can only start from pending while recovered
    failed jobs have an explicit, auditable transition back to pending.
    """
    if scan.status != SCAN_STATUS_FAILED:
        raise ValueError(
            f"Cannot retry scan {scan.id} from status "
            f"'{scan.status}'."
        )

    scan.status = SCAN_STATUS_PENDING
    scan.started_at = None
    scan.completed_at = None
    scan.error_message = None

    db.commit()
    db.refresh(scan)

    return scan


def list_scans(
    db: Session,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    total = db.query(Scan).count()

    statement = (
        select(Scan)
        .order_by(Scan.id.desc())
        .limit(limit)
        .offset(offset)
    )

    scans = list(db.scalars(statement).all())

    history = []

    for scan in scans:
        findings = (
            db.query(Finding)
            .filter(Finding.scan_id == scan.id)
            .all()
        )

        counts = build_finding_counts(findings)

        history.append(
            {
                "id": scan.id,
                "provider": scan.provider,
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "error_message": scan.error_message,
                **counts,
            }
        )

    return {
        "items": history,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
