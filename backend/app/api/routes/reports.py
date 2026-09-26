from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.user import User
from backend.app.services.finding_lifecycle_service import get_scan_lifecycle
from backend.app.services.scan_execution_error_service import get_execution_errors
from reporting.html_report import render_scan_report


router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"],
)


@router.get(
    "/scans/{scan_id}/html",
    response_class=Response,
)
def get_scan_html_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Tenant scoping is deliberately applied at the scan lookup.
    # A scan belonging to another tenant is indistinguishable from
    # a missing scan and therefore returns 404.
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

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(
            Finding.severity.desc(),
            Finding.rule_id.asc(),
            Finding.resource_id.asc(),
        )
        .all()
    )

    execution_errors = get_execution_errors(
        db=db,
        scan_id=scan.id,
    )

    lifecycle = get_scan_lifecycle(
        db=db,
        scan_id=scan.id,
        tenant_id=current_user.tenant_id,
    )

    report = render_scan_report(
        scan=scan,
        findings=findings,
        execution_errors=execution_errors,
        lifecycle=lifecycle,
    )

    return Response(
        content=report,
        media_type="text/html",
        headers={
            "Content-Disposition": (
                f'inline; filename="cloudsentinel-scan-{scan.id}.html"'
            ),
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": (
                "default-src 'none'; "
                "style-src 'unsafe-inline'; "
                "img-src 'data:'; "
                "font-src 'none'; "
                "connect-src 'none'; "
                "frame-ancestors 'none'; "
                "base-uri 'none'; "
                "object-src 'none'; "
                "form-action 'none'"
            ),
        },
    )
