from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.finding_suppression import FindingSuppression
from backend.app.models.scan import Scan
from backend.app.services.finding_lifecycle_service import build_finding_identity


def _is_active(suppression: FindingSuppression | None) -> bool:
    if suppression is None:
        return False
    if suppression.expires_at is None:
        return True
    return suppression.expires_at > datetime.now(timezone.utc)


def get_suppression_for_finding(
    db: Session,
    *,
    finding: Finding,
    tenant_id: int,
) -> FindingSuppression | None:
    scan = db.query(Scan).filter(
        Scan.id == finding.scan_id,
        Scan.tenant_id == tenant_id,
    ).first()
    if scan is None or scan.cloud_account_id is None:
        return None

    fingerprint = build_finding_identity(finding).fingerprint
    return db.query(FindingSuppression).filter(
        FindingSuppression.tenant_id == tenant_id,
        FindingSuppression.cloud_account_id == scan.cloud_account_id,
        FindingSuppression.fingerprint == fingerprint,
    ).first()


def upsert_suppression(
    db: Session,
    *,
    finding: Finding,
    tenant_id: int,
    user_id: int,
    reason: str,
    expires_at: datetime | None,
) -> FindingSuppression:
    scan = db.query(Scan).filter(
        Scan.id == finding.scan_id,
        Scan.tenant_id == tenant_id,
    ).first()
    if scan is None or scan.cloud_account_id is None:
        raise ValueError("Finding is not associated with a cloud account.")

    now = datetime.now(timezone.utc)
    if expires_at is not None:
        if expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone.")
        if expires_at <= now:
            raise ValueError("expires_at must be in the future.")

    fingerprint = build_finding_identity(finding).fingerprint
    suppression = db.query(FindingSuppression).filter(
        FindingSuppression.tenant_id == tenant_id,
        FindingSuppression.cloud_account_id == scan.cloud_account_id,
        FindingSuppression.fingerprint == fingerprint,
    ).with_for_update().first()

    if suppression is None:
        suppression = FindingSuppression(
            tenant_id=tenant_id,
            cloud_account_id=scan.cloud_account_id,
            fingerprint=fingerprint,
            reason=reason,
            expires_at=expires_at,
            created_by_user_id=user_id,
        )
        db.add(suppression)
    else:
        suppression.reason = reason
        suppression.expires_at = expires_at
        suppression.created_by_user_id = user_id
        suppression.updated_at = now

    db.commit()
    db.refresh(suppression)
    return suppression


def delete_suppression(
    db: Session,
    *,
    finding: Finding,
    tenant_id: int,
) -> bool:
    suppression = get_suppression_for_finding(
        db=db,
        finding=finding,
        tenant_id=tenant_id,
    )
    if suppression is None:
        return False

    db.delete(suppression)
    db.commit()
    return True


def suppression_response(
    *,
    finding: Finding,
    suppression: FindingSuppression | None,
) -> dict:
    active = _is_active(suppression)
    return {
        "id": suppression.id if active and suppression else None,
        "finding_id": finding.id,
        "fingerprint": build_finding_identity(finding).fingerprint,
        "suppressed": active,
        "reason": suppression.reason if active and suppression else None,
        "expires_at": suppression.expires_at if active and suppression else None,
        "created_by_user_id": suppression.created_by_user_id if active and suppression else None,
        "created_at": suppression.created_at if active and suppression else None,
        "updated_at": suppression.updated_at if active and suppression else None,
    }
