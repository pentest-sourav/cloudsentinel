from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.services.report_service import get_scan_report_data
from backend.app.services.audit_service import (
    AUDIT_SUCCESS,
    safe_record_audit_event,
)
from reporting.html_report import render_scan_report
from reporting.pdf_report import render_scan_pdf


router = APIRouter(
    prefix="/api/v1/reports",
    tags=["Reports"],
)


def _get_report_data_or_404(
    *,
    db: Session,
    scan_id: int,
    tenant_id: int,
):
    report_data = get_scan_report_data(
        db=db,
        scan_id=scan_id,
        tenant_id=tenant_id,
    )

    if report_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )

    return report_data


def _report_security_headers() -> dict[str, str]:
    return {
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
    }


@router.get(
    "/scans/{scan_id}/html",
    response_class=Response,
)
def get_scan_html_report(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    report_data = _get_report_data_or_404(
        db=db,
        scan_id=scan_id,
        tenant_id=current_user.tenant_id,
    )

    safe_record_audit_event(
        db=db,
        action="report.view",
        status=AUDIT_SUCCESS,
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        resource_type="scan",
        resource_id=scan_id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        metadata={"format": "html"},
    )

    report = render_scan_report(
        scan=report_data.scan,
        findings=report_data.findings,
        execution_errors=report_data.execution_errors,
        lifecycle=report_data.lifecycle,
    )

    headers = _report_security_headers()
    headers["Content-Disposition"] = (
        f'inline; filename="cloudsentinel-scan-{scan_id}.html"'
    )

    return Response(
        content=report,
        media_type="text/html",
        headers=headers,
    )


@router.get(
    "/scans/{scan_id}/pdf",
    response_class=Response,
)
def get_scan_pdf_report(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    report_data = _get_report_data_or_404(
        db=db,
        scan_id=scan_id,
        tenant_id=current_user.tenant_id,
    )

    safe_record_audit_event(
        db=db,
        action="report.view",
        status=AUDIT_SUCCESS,
        tenant_id=current_user.tenant_id,
        user_id=current_user.id,
        resource_type="scan",
        resource_id=scan_id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
        metadata={"format": "pdf"},
    )

    report = render_scan_pdf(
        scan=report_data.scan,
        findings=report_data.findings,
        execution_errors=report_data.execution_errors,
        lifecycle=report_data.lifecycle,
    )

    headers = _report_security_headers()
    headers["Content-Disposition"] = (
        f'attachment; filename="cloudsentinel-scan-{scan_id}.pdf"'
    )

    return Response(
        content=report,
        media_type="application/pdf",
        headers=headers,
    )
