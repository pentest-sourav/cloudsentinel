from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from backend.app.api.authorization import (
    ROLE_ADMINISTRATOR,
    ROLE_OPERATOR,
    ROLE_OWNER,
    require_roles,
)
from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.schemas.scan import ScanCreate, ScanResponse
from backend.app.schemas.scan_history import ScanHistoryListResponse
from backend.app.schemas.scan_summary import ScanSummaryResponse
from backend.app.services.scan_queue import ScanJob, ScanQueue
from backend.app.services.scan_service import (
    clear_scan_history,
    create_scan,
    get_scan,
    list_scans,
)
from backend.app.services.scan_summary_service import get_scan_summary
from backend.app.services.audit_service import (
    AUDIT_FAILURE,
    AUDIT_SUCCESS,
    safe_record_audit_event,
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
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            ROLE_OWNER,
            ROLE_ADMINISTRATOR,
            ROLE_OPERATOR,
        ),
    ),
):
    try:
        scan = create_scan(
            db=db,
            provider=scan_data.provider,
            tenant_id=current_user.tenant_id,
            cloud_account_id=scan_data.cloud_account_id,
        )

    except ValueError as exc:
        safe_record_audit_event(
            db=db,
            action="scan.create",
            status=AUDIT_FAILURE,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            request_id=getattr(request.state, "request_id", None),
            ip_address=request.client.host if request.client else None,
            metadata={"reason": str(exc)[:200]},
        )
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
        safe_record_audit_event(
            db=db,
            action="scan.create",
            status=AUDIT_FAILURE,
            tenant_id=current_user.tenant_id,
            user_id=current_user.id,
            resource_type="scan",
            resource_id=scan.id,
            request_id=getattr(request.state, "request_id", None),
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "scan queue unavailable"},
        )
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

    safe_record_audit_event(
        db=db,
        action="scan.create",
        status=AUDIT_SUCCESS,
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        resource_type="scan",
        resource_id=scan.id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        metadata={
            "provider": scan.provider,
            "cloud_account_id": scan.cloud_account_id,
        },
    )

    return scan


@router.delete(
    "/history",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_scan_history(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR),
    ),
):
    deleted_count = clear_scan_history(
        db=db,
        tenant_id=current_user.tenant_id,
    )

    safe_record_audit_event(
        db=db,
        action="scan_history.delete",
        status=AUDIT_SUCCESS,
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        metadata={"deleted_scan_count": deleted_count},
    )

    return None


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

    queue = ScanQueue()
    try:
        scan.progress = queue.get_progress(scan_id)
    finally:
        queue.close()

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
        tenant_id=current_user.tenant_id,
    )

    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return summary


# live progress endpoint marker
