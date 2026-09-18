from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.scan import Scan
from backend.app.models.finding import Finding
from backend.app.services.scan_summary_service import build_finding_counts


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
