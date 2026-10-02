from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.models.cloud_account import CloudAccount
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.services.cloud_account_service import (
    SCAN_ELIGIBLE_ACCOUNT_STATUSES,
)
from backend.app.services.scan_execution_error_service import (
    clear_execution_errors,
)
from backend.app.services.scan_summary_service import (
    build_finding_counts,
)


SCAN_STATUS_PENDING = "pending"
SCAN_STATUS_RUNNING = "running"
SCAN_STATUS_COMPLETED = "completed"
SCAN_STATUS_FAILED = "failed"

DEFAULT_MAX_ATTEMPTS = 4

VALID_SCAN_STATUSES = {
    SCAN_STATUS_PENDING,
    SCAN_STATUS_RUNNING,
    SCAN_STATUS_COMPLETED,
    SCAN_STATUS_FAILED,
}


def create_scan(
    db: Session,
    provider: str,
    tenant_id: int,
    cloud_account_id: int,
) -> Scan:
    if provider != "aws":
        raise ValueError(
            f"Provider '{provider}' is not currently supported."
        )

    cloud_account = (
        db.query(CloudAccount)
        .filter(
            CloudAccount.id == cloud_account_id,
            CloudAccount.tenant_id == tenant_id,
        )
        .first()
    )

    if cloud_account is None:
        raise ValueError(
            f"Cloud account {cloud_account_id} not found."
        )

    if cloud_account.provider != provider:
        raise ValueError(
            f"Cloud account {cloud_account_id} belongs to "
            f"provider '{cloud_account.provider}', not '{provider}'."
        )

    if cloud_account.status not in SCAN_ELIGIBLE_ACCOUNT_STATUSES:
        raise ValueError(
            f"Cloud account {cloud_account_id} is not connected."
        )

    scan = Scan(
        tenant_id=tenant_id,
        cloud_account_id=cloud_account_id,
        provider=provider,
        status=SCAN_STATUS_PENDING,
        attempt_count=0,
        max_attempts=DEFAULT_MAX_ATTEMPTS,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def get_scan(
    db: Session,
    scan_id: int,
    tenant_id: int,
) -> Scan | None:
    return (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.tenant_id == tenant_id,
        )
        .first()
    )


def get_scan_for_worker(
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

    if scan.attempt_count >= scan.max_attempts:
        raise ValueError(
            f"Scan {scan.id} has exhausted its maximum attempts."
        )

    # Serialize the state transition at the DB level. If another worker
    # loaded the same Redis job concurrently, only one transaction can
    # move the row from pending -> running.
    locked_scan = (
        db.query(Scan)
        .filter(Scan.id == scan.id)
        .with_for_update()
        .one()
    )

    if locked_scan.status != SCAN_STATUS_PENDING:
        raise ValueError(
            f"Scan {scan.id} was already claimed by another worker."
        )

    if locked_scan.attempt_count >= locked_scan.max_attempts:
        raise ValueError(
            f"Scan {scan.id} has exhausted its maximum attempts."
        )

    locked_scan.status = SCAN_STATUS_RUNNING
    locked_scan.started_at = datetime.now(timezone.utc)
    locked_scan.completed_at = None
    locked_scan.error_message = None
    locked_scan.attempt_count += 1
    locked_scan.updated_at = datetime.now(timezone.utc)

    clear_execution_errors(
        db=db,
        scan_id=locked_scan.id,
        commit=False,
    )

    # Commit the state transition and execution-error cleanup together.
    # This keeps the FOR UPDATE lock held until the complete transition
    # is durable and prevents another worker from claiming the same scan
    # between the cleanup and state update.
    db.commit()
    db.refresh(locked_scan)

    return locked_scan


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
    scan.updated_at = datetime.now(timezone.utc)

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
    scan.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    return scan


def retry_scan(
    db: Session,
    scan: Scan,
) -> Scan:
    if scan.status != SCAN_STATUS_FAILED:
        raise ValueError(
            f"Cannot retry scan {scan.id} from status "
            f"'{scan.status}'."
        )

    if scan.attempt_count >= scan.max_attempts:
        raise ValueError(
            f"Scan {scan.id} has exhausted its maximum attempts."
        )

    scan.status = SCAN_STATUS_PENDING
    scan.started_at = None
    scan.completed_at = None
    scan.error_message = None
    scan.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(scan)

    return scan


def _delete_scans(
    db: Session,
    scans: list[Scan],
) -> int:
    if not scans:
        return 0

    scan_ids = [scan.id for scan in scans]

    db.query(Finding).filter(
        Finding.scan_id.in_(scan_ids),
    ).delete(
        synchronize_session=False,
    )

    for scan in scans:
        db.delete(scan)

    return len(scans)


def delete_scans_for_cloud_account(
    db: Session,
    tenant_id: int,
    cloud_account_id: int,
) -> int:
    scans = (
        db.query(Scan)
        .filter(
            Scan.tenant_id == tenant_id,
            Scan.cloud_account_id == cloud_account_id,
        )
        .all()
    )

    deleted = _delete_scans(
        db=db,
        scans=scans,
    )

    if deleted:
        db.commit()

    return deleted


def clear_scan_history(
    db: Session,
    tenant_id: int,
) -> int:
    scans = (
        db.query(Scan)
        .filter(
            Scan.tenant_id == tenant_id,
        )
        .order_by(Scan.id.asc())
        .all()
    )

    deleted_count = _delete_scans(
        db=db,
        scans=scans,
    )

    db.commit()

    return deleted_count


def list_scans(
    db: Session,
    tenant_id: int,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    base_query = db.query(Scan).filter(
        Scan.tenant_id == tenant_id,
    )

    total = base_query.count()

    statement = (
        select(Scan)
        .where(Scan.tenant_id == tenant_id)
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
                "cloud_account_id": scan.cloud_account_id,
                "provider": scan.provider,
                "status": scan.status,
                "started_at": scan.started_at,
                "completed_at": scan.completed_at,
                "error_message": scan.error_message,
                "attempt_count": scan.attempt_count,
                "max_attempts": scan.max_attempts,
                **counts,
            }
        )

    return {
        "items": history,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
