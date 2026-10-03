from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.schemas.scan_summary import RiskPostureSummary
from backend.app.services.compliance_service import get_compliance_posture
from backend.app.services.risk_graph_service import get_risk_graph
from backend.app.services.scan_summary_service import get_scan_summary
from backend.app.services.posture_service import get_posture_trend


def _priority_reason(
    *,
    risk_score: float,
    internet_exposed: bool,
    sensitive_data: bool,
    asset_criticality: int,
) -> str:
    signals = []

    if risk_score >= 9:
        signals.append("critical risk")
    elif risk_score >= 7:
        signals.append("high risk")

    if internet_exposed:
        signals.append("internet exposed")

    if sensitive_data:
        signals.append("sensitive-data signal")

    if asset_criticality >= 4:
        signals.append("high asset criticality")

    if not signals:
        return "Risk score indicates remediation attention."

    return " + ".join(signals).capitalize() + "."


def get_dashboard_overview(
    *,
    db: Session,
    tenant_id: int,
    cloud_account_id: int | None = None,
) -> dict:
    query = (
        db.query(Scan)
        .filter(
            Scan.tenant_id == tenant_id,
            Scan.provider == "aws",
        )
    )

    if cloud_account_id is not None:
        query = query.filter(
            Scan.cloud_account_id == cloud_account_id,
        )

    latest_scan = (
        query.order_by(
            Scan.completed_at.desc().nullslast(),
            Scan.id.desc(),
        )
        .first()
    )

    trend = get_posture_trend(
        db=db,
        tenant_id=tenant_id,
        cloud_account_id=cloud_account_id,
        limit=12,
    )

    if latest_scan is None:
        return {
            "provider": "aws",
            "latest_scan_id": None,
            "latest_scan_status": None,
            "latest_scan_completed_at": None,
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "posture_score": 100.0,
            "posture_grade": "A",
            "average_risk_score": 0.0,
            "max_risk_score": 0.0,
            "affected_resource_count": 0,
            "exposed_asset_count": 0,
            "sensitive_asset_count": 0,
            "attack_path_count": 0,
            "risk_trend": trend["items"],
            "compliance": None,
            "top_risks": [],
            "data_quality_notes": [
                "No AWS scan has been run for this workspace yet.",
            ],
        }

    summary = get_scan_summary(
        db=db,
        scan_id=latest_scan.id,
        tenant_id=tenant_id,
    )

    graph = get_risk_graph(
        db=db,
        tenant_id=tenant_id,
        scan_id=latest_scan.id,
    )

    if summary is None or graph is None:
        raise RuntimeError(
            "Dashboard data could not be assembled for the latest scan."
        )

    risk_posture = summary["risk_posture"]
    graph_assets = {
        (
            asset["resource_type"],
            asset["resource_id"],
            asset["region"],
        ): asset
        for asset in graph["assets"]
    }

    top_risks = []
    for item in risk_posture["top_risks"]:
        asset = graph_assets.get(
            (
                item["resource_type"],
                item["resource_id"],
                item["region"],
            ),
            {},
        )
        internet_exposed = bool(asset.get("internet_exposed", False))
        sensitive_data = bool(asset.get("sensitive_data", False))
        asset_criticality = int(asset.get("asset_criticality", 1))

        top_risks.append(
            {
                **item,
                "internet_exposed": internet_exposed,
                "sensitive_data": sensitive_data,
                "asset_criticality": asset_criticality,
                "priority_reason": _priority_reason(
                    risk_score=float(item["risk_score"]),
                    internet_exposed=internet_exposed,
                    sensitive_data=sensitive_data,
                    asset_criticality=asset_criticality,
                ),
            }
        )

    notes = []
    if latest_scan.status not in {
        "completed",
        "completed_with_warnings",
    }:
        notes.append(
            "Latest scan is not terminal; posture and graph data may still change."
        )

    if summary["execution_error_count"] > 0:
        notes.append(
            f"{summary['execution_error_count']} scanner execution error(s) "
            "were recorded; affected controls may be incomplete."
        )

    compliance = None
    if latest_scan.status in {
        "completed",
        "completed_with_warnings",
    }:
        compliance = get_compliance_posture(
            db=db,
            tenant_id=tenant_id,
            scan_id=latest_scan.id,
            cloud_account_id=cloud_account_id,
        )
        if compliance and compliance["items"]:
            compliance = {
                "items": compliance["items"],
                "note": compliance["note"],
            }
        elif compliance:
            compliance = {
                "items": [],
                "note": compliance["note"],
            }

    return {
        "provider": latest_scan.provider,
        "latest_scan_id": latest_scan.id,
        "latest_scan_status": latest_scan.status,
        "latest_scan_completed_at": latest_scan.completed_at,
        "total_findings": summary["total_findings"],
        "critical_count": summary["critical_count"],
        "high_count": summary["high_count"],
        "medium_count": summary["medium_count"],
        "low_count": summary["low_count"],
        "info_count": summary["info_count"],
        "posture_score": risk_posture["score"],
        "posture_grade": risk_posture["grade"],
        "average_risk_score": risk_posture["average_risk_score"],
        "max_risk_score": risk_posture["max_risk_score"],
        "affected_resource_count": risk_posture["affected_resource_count"],
        "exposed_asset_count": graph["exposed_asset_count"],
        "sensitive_asset_count": graph["sensitive_asset_count"],
        "attack_path_count": len(graph["attack_paths"]),
        "risk_trend": trend["items"],
        "compliance": compliance,
        "top_risks": top_risks,
        "data_quality_notes": notes,
    }
