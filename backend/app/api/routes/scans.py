from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.schemas.scan_history import ScanHistoryListResponse
from backend.app.schemas.scan_summary import ScanSummaryResponse
from backend.app.services.scan_queue import ScanJob, ScanQueue
from backend.app.services.scan_service import (
    create_scan,
    get_scan,
    list_scans,
)
from backend.app.services.scan_summary_service import get_scan_summary


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
    current_user: User = Depends(get_current_user),
):
    if scan_data.provider != "aws":
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                f"Provider '{scan_data.provider}' is not yet "
                "supported for scanning."
            ),
        )

    try:
        scan = create_scan(
            db=db,
            provider=scan_data.provider,
            tenant_id=current_user.tenant_id,
            cloud_account_id=scan_data.cloud_account_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

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
    current_user: User = Depends(get_current_user),
):
    return list_scans(
        db=db,
        tenant_id=current_user.tenant_id,
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
    current_user: User = Depends(get_current_user),
):
    scan = get_scan(
        db=db,
        scan_id=scan_id,
        tenant_id=current_user.tenant_id,
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
    current_user: User = Depends(get_current_user),
):
    scan = get_scan(
        db=db,
        scan_id=scan_id,
        tenant_id=current_user.tenant_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

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
