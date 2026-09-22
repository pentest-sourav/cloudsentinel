from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.schemas.scan_history import (
    ScanHistoryListResponse,
)
from backend.app.schemas.scan_summary import ScanSummaryResponse
from backend.app.services.scan_queue import ScanJob, ScanQueue
from backend.app.services.scan_service import (
    create_scan,
    get_scan,
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
    if scan_data.provider != "aws":
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                f"Provider '{scan_data.provider}' is not yet "
                "supported for scanning."
            ),
        )

    scan = create_scan(
        db=db,
        provider=scan_data.provider,
    )

    queue = ScanQueue()

    try:
        queue.enqueue(
            ScanJob(
                scan_id=scan.id,
                provider=scan.provider,
            )
        )
    except Exception as exc:
        scan.status = "failed"
        scan.error_message = (
            f"Unable to enqueue scan job: {exc}"
        )[:4000]
        db.commit()
        db.refresh(scan)

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Scan queue is unavailable.",
        ) from exc
    finally:
        queue.close()

    return scan


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
    "/{scan_id}",
    response_model=ScanResponse,
)
def get_scan_by_id(
    scan_id: int,
    db: Session = Depends(get_db),
):
    scan = get_scan(
        db=db,
        scan_id=scan_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return scan


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
