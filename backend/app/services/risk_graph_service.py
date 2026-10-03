from collections import defaultdict

from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan


def _signal(evidence: dict, key: str) -> bool:
    if key == "internet_exposed":
        return bool(
            evidence.get(
                "internet_exposed",
                evidence.get("public_access_signal", False),
            )
        )
    return bool(evidence.get(key, False))


def _bounded_int(value: object, default: int = 1) -> int:
    try:
        return max(1, min(5, int(value)))
    except (TypeError, ValueError):
        return default


def get_risk_graph(
    *,
    db: Session,
    tenant_id: int,
    scan_id: int,
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
        .order_by(Finding.risk_score.desc(), Finding.id.desc())
        .yield_per(1000)
    )

    assets: dict[tuple[str, str, str], dict] = {}
    relationships: list[dict] = []

    for finding in findings:
        key = (
            finding.resource_type,
            finding.resource_id,
            finding.region,
        )
        evidence = finding.evidence or {}

        asset = assets.setdefault(
            key,
            {
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
                "region": finding.region,
                "finding_count": 0,
                "risk_scores": [],
                "risk_levels": [],
                "internet_exposed": False,
                "sensitive_data": False,
                "asset_criticality": 1,
                "exploitability": 1,
            },
        )

        asset["finding_count"] += 1
        asset["risk_scores"].append(float(finding.risk_score))
        asset["risk_levels"].append(finding.risk_level)

        asset["internet_exposed"] = (
            asset["internet_exposed"]
            or _signal(evidence, "internet_exposed")
        )
        asset["sensitive_data"] = (
            asset["sensitive_data"]
            or _signal(evidence, "sensitive_data")
        )
        asset["asset_criticality"] = max(
            asset["asset_criticality"],
            _bounded_int(evidence.get("asset_criticality")),
        )
        asset["exploitability"] = max(
            asset["exploitability"],
            _bounded_int(evidence.get("exploitability")),
        )

        resource_key = (
            f"resource:{finding.resource_type}:"
            f"{finding.resource_id}:{finding.region}"
        )
        finding_key = f"finding:{finding.id}"

        relationships.append(
            {
                "source": finding_key,
                "target": resource_key,
                "relationship": "affects",
                "evidence_derived": True,
            }
        )

    severity_order = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    asset_rows = []
    attack_paths = []

    for asset in assets.values():
        scores = asset["risk_scores"]
        levels = asset["risk_levels"]
        highest_level = max(
            levels,
            key=lambda value: severity_order.get(value.lower(), 0),
        )

        resource_key = (
            f"resource:{asset['resource_type']}:"
            f"{asset['resource_id']}:{asset['region']}"
        )

        asset_rows.append(
            {
                "resource_type": asset["resource_type"],
                "resource_id": asset["resource_id"],
                "region": asset["region"],
                "finding_count": asset["finding_count"],
                "max_risk_score": round(max(scores), 2),
                "average_risk_score": round(sum(scores) / len(scores), 2),
                "highest_risk_level": highest_level,
                "internet_exposed": asset["internet_exposed"],
                "sensitive_data": asset["sensitive_data"],
                "asset_criticality": asset["asset_criticality"],
                "exploitability": asset["exploitability"],
            }
        )

        if asset["internet_exposed"] and asset["sensitive_data"]:
            relationships.append(
                {
                    "source": "signal:internet-exposure",
                    "target": resource_key,
                    "relationship": "exposes",
                    "evidence_derived": True,
                }
            )
            relationships.append(
                {
                    "source": resource_key,
                    "target": "signal:sensitive-data",
                    "relationship": "contains-sensitive-data-signal",
                    "evidence_derived": True,
                }
            )
            attack_paths.append(
                {
                    "path_id": f"ap-sensitive-{asset['resource_type']}-{asset['resource_id']}",
                    "title": "Internet exposure to sensitive-data asset",
                    "risk_level": "critical"
                    if asset["asset_criticality"] >= 4
                    else "high",
                    "resource_type": asset["resource_type"],
                    "resource_id": asset["resource_id"],
                    "region": asset["region"],
                    "confidence": "high",
                    "steps": [
                        "Internet exposure signal",
                        f"Reach {asset['resource_type']} {asset['resource_id']}",
                        "Sensitive-data signal",
                    ],
                    "rationale": (
                        "Both internet exposure and sensitive-data signals "
                        "are present in scanner evidence for this asset."
                    ),
                }
            )
        elif asset["internet_exposed"] and asset["asset_criticality"] >= 4:
            relationships.append(
                {
                    "source": "signal:internet-exposure",
                    "target": resource_key,
                    "relationship": "exposes",
                    "evidence_derived": True,
                }
            )
            attack_paths.append(
                {
                    "path_id": f"ap-critical-{asset['resource_type']}-{asset['resource_id']}",
                    "title": "Internet exposure to critical asset",
                    "risk_level": "high",
                    "resource_type": asset["resource_type"],
                    "resource_id": asset["resource_id"],
                    "region": asset["region"],
                    "confidence": "medium",
                    "steps": [
                        "Internet exposure signal",
                        f"Reach {asset['resource_type']} {asset['resource_id']}",
                        "High asset-criticality signal",
                    ],
                    "rationale": (
                        "Internet exposure and a high asset-criticality "
                        "signal are both present in scanner evidence."
                    ),
                }
            )

    asset_rows.sort(
        key=lambda item: (
            item["max_risk_score"],
            item["finding_count"],
        ),
        reverse=True,
    )
    attack_paths.sort(
        key=lambda item: (
            severity_order.get(item["risk_level"], 0),
            item["confidence"],
        ),
        reverse=True,
    )

    return {
        "scan_id": scan.id,
        "provider": scan.provider,
        "status": scan.status,
        "graph_type": "evidence-derived-risk-graph",
        "evidence_derived": True,
        "asset_count": len(asset_rows),
        "finding_count": sum(
            asset["finding_count"] for asset in asset_rows
        ),
        "exposed_asset_count": sum(
            1 for asset in asset_rows if asset["internet_exposed"]
        ),
        "sensitive_asset_count": sum(
            1 for asset in asset_rows if asset["sensitive_data"]
        ),
        "assets": asset_rows[:100],
        "relationships": relationships[:500],
        "attack_paths": attack_paths[:50],
    }
