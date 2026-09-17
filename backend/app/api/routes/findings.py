from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.schemas.finding import FindingResponse
from backend.app.services.finding_service import (
    get_finding,
    get_findings_by_scan,
)

router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)


@router.get("/scan/{scan_id}", response_model=list[FindingResponse])
def list_scan_findings(
    scan_id: int,
    db: Session = Depends(get_db),
):
    return get_findings_by_scan(
        db=db,
        scan_id=scan_id,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
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
