from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.api.authorization import ROLE_ADMINISTRATOR, ROLE_OWNER, require_roles
from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.schemas.alert_policy import AlertPolicyRequest
from backend.app.schemas.alert_policy_response import AlertPolicyResponse
from backend.app.services.alert_policy_service import (
    create_policy,
    delete_policy,
    list_policies,
    policy_response,
)

router = APIRouter(prefix="/api/v1/alert-policies", tags=["Alert Policies"])


@router.get("", response_model=list[AlertPolicyResponse])
def get_alert_policies(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return [policy_response(p) for p in list_policies(db, current_user.tenant_id)]


@router.post("", response_model=AlertPolicyResponse, status_code=status.HTTP_201_CREATED)
def create_alert_policy(
    payload: AlertPolicyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR)),
):
    try:
        policy = create_policy(
            db=db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            name=payload.name.strip(),
            endpoint_url=str(payload.endpoint_url),
            min_severity=payload.min_severity,
            events=payload.events,
            secret=payload.secret,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return policy_response(policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_alert_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR)),
):
    if not delete_policy(db=db, tenant_id=current_user.tenant_id, policy_id=policy_id):
        raise HTTPException(status_code=404, detail="Alert policy not found")
    return None
