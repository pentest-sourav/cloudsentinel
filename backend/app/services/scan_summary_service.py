from sqlalchemy import func
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

    # Summary endpoints are called repeatedly while a scan is running.
    # Aggregate severity counts in SQL instead of materializing every finding
    # row on every poll; this keeps the API cheap for large scans.
    rows = (
        db.query(
            Finding.severity,
            func.count(Finding.id),
        )
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
        .all()
    )

    counts = {
        "total_findings": 0,
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    }

    key_by_severity = {
        "critical": "critical_count",
        "high": "high_count",
        "medium": "medium_count",
        "low": "low_count",
        "info": "info_count",
    }

    for severity, count in rows:
        counts["total_findings"] += count
        count_key = key_by_severity.get(severity.lower())

        if count_key is not None:
            counts[count_key] += count

    execution_errors = get_execution_errors(
        db=db,
        scan_id=scan_id,
    )

    return {
        "scan_id": scan.id,
        "provider": scan.provider,
        "status": scan.status,
        **counts,
        "execution_error_count": len(execution_errors),
        "execution_errors": execution_errors,
    }
