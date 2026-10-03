from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.orm import Session

from backend.app.models.audit_event import AuditEvent


AUDIT_SUCCESS = "success"
AUDIT_FAILURE = "failure"


def record_audit_event(
    *,
    db: Session,
    action: str,
    status: str,
    tenant_id: int | None = None,
    user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: str | int | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        tenant_id=tenant_id,
        user_id=user_id,
        action=action,
        status=status,
        resource_type=resource_type,
        resource_id=(
            str(resource_id)
            if resource_id is not None
            else None
        ),
        request_id=request_id,
        ip_address=ip_address,
        metadata=dict(metadata or {}),
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def safe_record_audit_event(
    **kwargs,
) -> None:
    """
    Best-effort audit logging helper.

    Security telemetry must not turn a customer API operation into a
    500 because the audit sink is unavailable. Callers that need the
    audit event transactionally should use record_audit_event().
    """
    db: Session = kwargs["db"]
    try:
        record_audit_event(**kwargs)
    except Exception:
        db.rollback()


def purge_expired_audit_events(
    *,
    db: Session,
    retention_days: int,
) -> int:
    if retention_days <= 0:
        raise ValueError("retention_days must be > 0")

    cutoff = datetime.now(timezone.utc) - timedelta(
        days=retention_days,
    )

    result = db.execute(
        delete(AuditEvent).where(
            AuditEvent.created_at < cutoff,
        )
    )
    db.commit()
    return int(result.rowcount or 0)


def list_audit_events(
    *,
    db: Session,
    tenant_id: int,
    limit: int,
    offset: int,
    action: str | None = None,
    status: str | None = None,
    resource_type: str | None = None,
):
    """Return paginated audit events scoped to one tenant."""
    from sqlalchemy import func, select

    query = select(AuditEvent).where(
        AuditEvent.tenant_id == tenant_id,
    )
    count_query = select(func.count(AuditEvent.id)).where(
        AuditEvent.tenant_id == tenant_id,
    )

    if action:
        query = query.where(AuditEvent.action == action)
        count_query = count_query.where(AuditEvent.action == action)

    if status:
        query = query.where(AuditEvent.status == status)
        count_query = count_query.where(AuditEvent.status == status)

    if resource_type:
        query = query.where(AuditEvent.resource_type == resource_type)
        count_query = count_query.where(AuditEvent.resource_type == resource_type)

    total = int(db.execute(count_query).scalar_one())
    events = db.execute(
        query.order_by(
            AuditEvent.created_at.desc(),
            AuditEvent.id.desc(),
        ).limit(limit).offset(offset)
    ).scalars().all()

    return {
        "items": events,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
