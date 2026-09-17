from sqlalchemy.orm import Session

from backend.app.models.scan import Scan
from backend.app.models.finding import Finding


def get_scan_summary(
    db: Session,
    scan_id: int,
) -> dict:
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if scan is None:
        return None

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .all()
    )

    summary = {
        "scan_id": scan.id,
        "provider": scan.provider,
        "status": scan.status,
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
            summary["critical_count"] += 1
        elif severity == "high":
            summary["high_count"] += 1
        elif severity == "medium":
            summary["medium_count"] += 1
        elif severity == "low":
            summary["low_count"] += 1
        elif severity == "info":
            summary["info_count"] += 1

    return summary
