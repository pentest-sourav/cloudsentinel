from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.services.finding_lifecycle_service import get_scan_lifecycle
from backend.app.services.scan_execution_error_service import get_execution_errors


@dataclass(frozen=True)
class ScanReportData:
    scan: Scan
    findings: list[Finding]
    execution_errors: list
    lifecycle: dict | None


def get_scan_report_data(
    *,
    db: Session,
    scan_id: int,
    tenant_id: int,
) -> ScanReportData | None:
    """
    Load the complete report dataset for a scan.

    Tenant scoping is applied at the scan lookup so callers cannot
    retrieve report data belonging to another tenant.
    """
    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.tenant_id == tenant_id,
        )
        .first()
    )

    if scan is None:
        return None

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
        tenant_id=tenant_id,
    )

    return ScanReportData(
        scan=scan,
        findings=findings,
        execution_errors=execution_errors,
        lifecycle=lifecycle,
    )
