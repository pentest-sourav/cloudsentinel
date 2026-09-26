from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

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
from backend.app.services.finding_lifecycle_service import (
    get_scan_lifecycle,
)
from backend.app.services.finding_service import (
    get_finding,
    get_findings_by_scan,
)


router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
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
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    severity: Literal[
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ] | None = Query(
        default=None,
    ),
    risk_level: Literal[
        "critical",
        "high",
        "medium",
        "low",
        "info",
    ] | None = Query(
        default=None,
    ),
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
    "/{finding_id}",
    response_model=FindingResponse,
)
def get_finding_by_id(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = (
        db.query(Finding)
        .join(
            Scan,
            Finding.scan_id == Scan.id,
        )
        .filter(
            Finding.id == finding_id,
            Scan.tenant_id == current_user.tenant_id,
        )
        .first()
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return get_finding(
        db=db,
        finding_id=finding_id,
    )
