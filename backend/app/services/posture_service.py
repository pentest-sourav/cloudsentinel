from sqlalchemy import case, func
from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.models.scan_execution_error import ScanExecutionError


_TERMINAL_SCAN_STATUSES = (
    "completed",
    "completed_with_warnings",
)


def get_posture_trend(
    *,
    db: Session,
    tenant_id: int,
    cloud_account_id: int | None = None,
    limit: int = 30,
) -> dict:
    query = (
        db.query(
            Scan.id.label("scan_id"),
            Scan.cloud_account_id.label("cloud_account_id"),
            Scan.provider.label("provider"),
            Scan.status.label("status"),
            Scan.completed_at.label("completed_at"),
            func.count(Finding.id).label("total_findings"),
            func.coalesce(
                func.sum(
                    case(
                        (Finding.severity == "critical", 1),
                        else_=0,
                    )
                ),
                0,
            ).label("critical_count"),
            func.coalesce(
                func.sum(
                    case(
                        (Finding.severity == "high", 1),
                        else_=0,
                    )
                ),
                0,
            ).label("high_count"),
            func.coalesce(
                func.sum(
                    case(
                        (Finding.severity == "medium", 1),
                        else_=0,
                    )
                ),
                0,
            ).label("medium_count"),
            func.coalesce(
                func.sum(
                    case(
                        (Finding.severity == "low", 1),
                        else_=0,
                    )
                ),
                0,
            ).label("low_count"),
            func.coalesce(
                func.sum(
                    case(
                        (Finding.severity == "info", 1),
                        else_=0,
                    )
                ),
                0,
            ).label("info_count"),
            func.coalesce(
                func.sum(Finding.risk_score),
                0.0,
            ).label("risk_score_sum"),
        )
        .outerjoin(
            Finding,
            Finding.scan_id == Scan.id,
        )
        .filter(
            Scan.tenant_id == tenant_id,
            Scan.provider == "aws",
            Scan.status.in_(_TERMINAL_SCAN_STATUSES),
        )
    )

    if cloud_account_id is not None:
        query = query.filter(
            Scan.cloud_account_id == cloud_account_id,
        )

    rows = (
        query.group_by(
            Scan.id,
            Scan.cloud_account_id,
            Scan.provider,
            Scan.status,
            Scan.completed_at,
        )
        .order_by(
            Scan.completed_at.desc(),
            Scan.id.desc(),
        )
        .limit(limit)
        .all()
    )

    scan_ids = [row.scan_id for row in rows]

    error_counts = {}
    if scan_ids:
        error_rows = (
            db.query(
                ScanExecutionError.scan_id,
                func.count(ScanExecutionError.id),
            )
            .filter(
                ScanExecutionError.scan_id.in_(scan_ids),
            )
            .group_by(ScanExecutionError.scan_id)
            .all()
        )
        error_counts = {
            scan_id: int(count)
            for scan_id, count in error_rows
        }

    return {
        "items": [
            {
                "scan_id": row.scan_id,
                "cloud_account_id": row.cloud_account_id,
                "provider": row.provider,
                "status": row.status,
                "completed_at": row.completed_at,
                "total_findings": int(row.total_findings),
                "critical_count": int(row.critical_count),
                "high_count": int(row.high_count),
                "medium_count": int(row.medium_count),
                "low_count": int(row.low_count),
                "info_count": int(row.info_count),
                "risk_score_sum": float(row.risk_score_sum),
                "execution_error_count": error_counts.get(
                    row.scan_id,
                    0,
                ),
            }
            for row in rows
        ],
        "limit": limit,
        "cloud_account_id": cloud_account_id,
    }
