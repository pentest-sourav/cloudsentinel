from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.authorization import (
    ROLE_ADMINISTRATOR,
    ROLE_OPERATOR,
    ROLE_OWNER,
    require_roles,
)
from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.user import User
from backend.app.schemas.finding import (
    FindingListResponse,
    FindingResponse,
)
from backend.app.schemas.finding_lifecycle import (
    FindingLifecycleResponse,
)
from backend.app.schemas.finding_suppression import (
    FindingSuppressionRequest,
    FindingSuppressionResponse,
)
from backend.app.services.audit_service import (
    AUDIT_FAILURE,
    AUDIT_SUCCESS,
    record_audit_event,
)
from backend.app.services.finding_lifecycle_service import (
    get_scan_lifecycle,
)
from backend.app.services.finding_service import (
    get_finding,
    get_findings_by_scan,
)
from backend.app.services.finding_suppression_service import (
    delete_suppression,
    get_suppression_for_finding,
    suppression_response,
    upsert_suppression,
)


router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)


def _get_tenant_finding(
    db: Session,
    finding_id: int,
    tenant_id: int,
) -> Finding | None:
    return (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Finding.id == finding_id,
            Scan.tenant_id == tenant_id,
        )
        .first()
    )


@router.get(
    "/scan/{scan_id}/lifecycle",
    response_model=FindingLifecycleResponse,
)
def get_scan_finding_lifecycle(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = get_scan_lifecycle(
        db=db,
        scan_id=scan_id,
        tenant_id=current_user.tenant_id,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return result


@router.get(
    "/scan/{scan_id}",
    response_model=FindingListResponse,
)
def list_scan_findings(
    scan_id: int,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    severity: Literal[
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ] | None = Query(default=None),
    risk_level: Literal[
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ] | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.tenant_id == current_user.tenant_id,
        )
        .first()
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    result = get_findings_by_scan(
        db=db,
        scan_id=scan_id,
        tenant_id=current_user.tenant_id,
        limit=limit,
        offset=offset,
        severity=severity,
        risk_level=risk_level,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return result


@router.get(
    "/{finding_id}/suppression",
    response_model=FindingSuppressionResponse,
)
def get_finding_suppression(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = _get_tenant_finding(
        db=db,
        finding_id=finding_id,
        tenant_id=current_user.tenant_id,
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    suppression = get_suppression_for_finding(
        db=db,
        finding=finding,
        tenant_id=current_user.tenant_id,
    )
    return suppression_response(
        finding=finding,
        suppression=suppression,
    )


@router.post(
    "/{finding_id}/suppression",
    response_model=FindingSuppressionResponse,
)
def suppress_finding(
    finding_id: int,
    payload: FindingSuppressionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            ROLE_OWNER,
            ROLE_ADMINISTRATOR,
            ROLE_OPERATOR,
        )
    ),
):
    finding = _get_tenant_finding(
        db=db,
        finding_id=finding_id,
        tenant_id=current_user.tenant_id,
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    try:
        suppression = upsert_suppression(
            db=db,
            finding=finding,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            reason=payload.reason,
            expires_at=payload.expires_at,
        )
    except ValueError as exc:
        record_audit_event(
            db=db,
            action="finding.suppression.create",
            status=AUDIT_FAILURE,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            resource_type="finding",
            resource_id=finding_id,
            metadata={"reason": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    record_audit_event(
        db=db,
        action="finding.suppression.create",
        status=AUDIT_SUCCESS,
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        resource_type="finding",
        resource_id=finding_id,
        metadata={
            "suppression_id": suppression.id,
            "fingerprint": suppression.fingerprint,
            "expires_at": (
                suppression.expires_at.isoformat()
                if suppression.expires_at is not None
                else None
            ),
        },
    )

    return suppression_response(
        finding=finding,
        suppression=suppression,
    )


@router.delete(
    "/{finding_id}/suppression",
    status_code=status.HTTP_204_NO_CONTENT,
)
def unsuppress_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            ROLE_OWNER,
            ROLE_ADMINISTRATOR,
            ROLE_OPERATOR,
        )
    ),
):
    finding = _get_tenant_finding(
        db=db,
        finding_id=finding_id,
        tenant_id=current_user.tenant_id,
    )
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    deleted = delete_suppression(
        db=db,
        finding=finding,
        tenant_id=current_user.tenant_id,
    )
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding is not suppressed",
        )

    record_audit_event(
        db=db,
        action="finding.suppression.delete",
        status=AUDIT_SUCCESS,
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        resource_type="finding",
        resource_id=finding_id,
    )

    return None


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
)
def get_finding_by_id(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = _get_tenant_finding(
        db=db,
        finding_id=finding_id,
        tenant_id=current_user.tenant_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return get_finding(
        db=db,
        finding_id=finding_id,
        tenant_id=current_user.tenant_id,
    )
