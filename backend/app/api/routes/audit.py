from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.api.authorization import (
    ROLE_ADMINISTRATOR,
    ROLE_OWNER,
    require_roles,
)
from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.schemas.audit import AuditEventListResponse
from backend.app.services.audit_service import list_audit_events


router = APIRouter(
    prefix="/api/v1/audit-events",
    tags=["Audit Events"],
)


@router.get(
    "",
    response_model=AuditEventListResponse,
)
def get_audit_events(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    action: str | None = Query(default=None, max_length=100),
    event_status: str | None = Query(
        default=None,
        alias="status",
        max_length=30,
    ),
    resource_type: str | None = Query(
        default=None,
        max_length=50,
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR),
    ),
):
    return list_audit_events(
        db=db,
        tenant_id=current_user.tenant_id,
        limit=limit,
        offset=offset,
        action=action,
        status=event_status,
        resource_type=resource_type,
    )
