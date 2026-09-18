from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.schemas.scan_history import (
    ScanHistoryListResponse,
)
from backend.app.schemas.scan_summary import ScanSummaryResponse
from backend.app.services.aws_scan_service import run_aws_scan
from backend.app.services.scan_runner import ScanRunner
from backend.app.services.scan_service import (
    create_scan,
    list_scans,
)
from backend.app.services.scan_summary_service import (
    get_scan_summary,
)

router = APIRouter(
    prefix="/api/v1/scans",
    tags=["Scans"],
)


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_new_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
):
    scan = create_scan(
        db=db,
        provider=scan_data.provider,
    )

    if scan_data.provider == "aws":
        scanner = run_aws_scan
    else:
        scanner = lambda: []

    runner = ScanRunner(db=db)

    return runner.run(
        scan=scan,
        scanner=scanner,
    )


@router.get(
    "",
    response_model=ScanHistoryListResponse,
)
def get_scans(
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    db: Session = Depends(get_db),
):
    return list_scans(
        db=db,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{scan_id}/summary",
    response_model=ScanSummaryResponse,
)
def get_scan_summary_by_id(
    scan_id: int,
    db: Session = Depends(get_db),
):
    summary = get_scan_summary(
        db=db,
        scan_id=scan_id,
    )

    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return summary
