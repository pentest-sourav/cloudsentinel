from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.schemas.finding import (
    FindingListResponse,
    FindingResponse,
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
):
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
):
    finding = get_finding(
        db=db,
        finding_id=finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    return finding
