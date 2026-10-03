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

    risk_posture = build_risk_posture(
        db=db,
        scan_id=scan_id,
    )

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
        "risk_posture": risk_posture,
    }


def _risk_posture_grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def build_risk_posture(
    db: Session,
    scan_id: int,
) -> dict:
    aggregate = (
        db.query(
            func.coalesce(func.avg(Finding.risk_score), 0.0),
            func.coalesce(func.max(Finding.risk_score), 0.0),
            func.coalesce(func.sum(Finding.risk_score), 0.0),
            func.count(func.distinct(Finding.resource_id)),
        )
        .filter(Finding.scan_id == scan_id)
        .one()
    )

    average_risk_score = round(float(aggregate[0]), 2)
    max_risk_score = round(float(aggregate[1]), 2)
    risk_score_sum = round(float(aggregate[2]), 2)
    affected_resource_count = int(aggregate[3])

    # This is a risk posture index, not a compliance percentage. It measures
    # the average effective finding risk on the existing 0-10 risk scale.
    score = round(max(0.0, min(100.0, 100.0 - average_risk_score * 10.0)), 1)

    top_risks = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc(), Finding.id.desc())
        .limit(5)
        .all()
    )

    return {
        "score": score,
        "grade": _risk_posture_grade(score),
        "average_risk_score": average_risk_score,
        "max_risk_score": max_risk_score,
        "risk_score_sum": risk_score_sum,
        "affected_resource_count": affected_resource_count,
        "top_risks": [
            {
                "finding_id": finding.id,
                "rule_id": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "risk_score": finding.risk_score,
                "risk_level": finding.risk_level,
                "provider": finding.provider,
                "region": finding.region,
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
            }
            for finding in top_risks
        ],
    }
