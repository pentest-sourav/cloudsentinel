from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.services.scan_execution_error_service import (
    get_execution_errors,
)


def build_finding_counts(findings: list[Finding]) -> dict:
    counts = {
        "total_findings": len(findings),
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    }

    for finding in findings:
        severity = finding.severity.lower()

        if severity == "critical":
            counts["critical_count"] += 1
        elif severity == "high":
            counts["high_count"] += 1
        elif severity == "medium":
            counts["medium_count"] += 1
        elif severity == "low":
            counts["low_count"] += 1
        elif severity == "info":
            counts["info_count"] += 1

    return counts


def get_scan_summary(
    db: Session,
    scan_id: int,
    tenant_id: int,
) -> dict | None:
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
        .filter(Finding.scan_id == scan_id)
        .all()
    )

    execution_errors = get_execution_errors(
        db=db,
        scan_id=scan_id,
    )

    counts = build_finding_counts(findings)

    return {
        "scan_id": scan.id,
        "provider": scan.provider,
        "status": scan.status,
        **counts,
        "execution_error_count": len(execution_errors),
        "execution_errors": execution_errors,
    }
