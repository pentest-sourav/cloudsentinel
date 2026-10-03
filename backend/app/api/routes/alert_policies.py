from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.authorization import ROLE_ADMINISTRATOR, ROLE_OWNER, require_roles
from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.models.alert_policy import AlertPolicy
from backend.app.schemas.alert_policy import AlertPolicyRequest, AlertPolicyUpdate
from backend.app.schemas.alert_policy_response import AlertPolicyResponse
from backend.app.schemas.alert_delivery import AlertDeliveryResponse
from backend.app.services.alert_policy_service import (
    create_policy,
    delete_policy,
    list_policies,
    policy_response,
    update_policy,
    list_deliveries,
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


@router.patch("/{policy_id}", response_model=AlertPolicyResponse)
def update_alert_policy(
    policy_id: int,
    payload: AlertPolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR)),
):
    try:
        policy = update_policy(
            db=db,
            tenant_id=current_user.tenant_id,
            policy_id=policy_id,
            name=payload.name,
            endpoint_url=str(payload.endpoint_url) if payload.endpoint_url else None,
            min_severity=payload.min_severity,
            events=payload.events,
            secret=payload.secret,
            rotate_secret=payload.rotate_secret,
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if policy is None:
        raise HTTPException(status_code=404, detail="Alert policy not found")
    return policy_response(policy)


@router.get("/{policy_id}/deliveries", response_model=list[AlertDeliveryResponse])
def get_alert_deliveries(
    policy_id: int,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    deliveries = list_deliveries(
        db=db,
        tenant_id=current_user.tenant_id,
        policy_id=policy_id,
        limit=limit,
        offset=offset,
    )
    if not deliveries and not db.query(AlertPolicy.id).filter(
        AlertPolicy.id == policy_id,
        AlertPolicy.tenant_id == current_user.tenant_id,
    ).first():
        raise HTTPException(status_code=404, detail="Alert policy not found")
    return deliveries


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_alert_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR)),
):
    if not delete_policy(db=db, tenant_id=current_user.tenant_id, policy_id=policy_id):
        raise HTTPException(status_code=404, detail="Alert policy not found")
    return None
