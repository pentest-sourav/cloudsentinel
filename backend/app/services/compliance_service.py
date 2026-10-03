from collections import defaultdict

from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan


def get_compliance_posture(
    *,
    db: Session,
    tenant_id: int,
    scan_id: int,
    cloud_account_id: int | None = None,
) -> dict | None:
    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.tenant_id == tenant_id,
            Scan.provider == "aws",
        )
        .first()
    )
    if scan is None:
        return None

    if cloud_account_id is not None and scan.cloud_account_id != cloud_account_id:
        return None

    if scan.status not in {"completed", "completed_with_warnings"}:
        return {
            "items": [],
            "scan_id": scan.id,
            "status": scan.status,
            "cloud_account_id": scan.cloud_account_id,
            "note": "Compliance posture is available only for terminal scans.",
        }

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .yield_per(1000)
    )

    grouped: dict[str, dict] = defaultdict(
        lambda: {
            "finding_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "rules": set(),
            "resources": set(),
        }
    )

    for finding in findings:
        frameworks = {
            str(value).strip()
            for value in (finding.compliance or [])
            if str(value).strip()
        }
        for framework in frameworks:
            item = grouped[framework]
            item["finding_count"] += 1
            severity_key = f"{finding.severity.lower()}_count"
            if severity_key in item:
                item[severity_key] += 1
            item["rules"].add(finding.rule_id)
            item["resources"].add(
                (finding.resource_type, finding.resource_id)
            )

    items = []
    for framework, value in sorted(grouped.items()):
        items.append(
            {
                "framework": framework,
                "finding_count": value["finding_count"],
                "critical_count": value["critical_count"],
                "high_count": value["high_count"],
                "medium_count": value["medium_count"],
                "low_count": value["low_count"],
                "info_count": value["info_count"],
                "affected_rules": len(value["rules"]),
                "affected_resources": len(value["resources"]),
            }
        )

    return {
        "items": items,
        "scan_id": scan.id,
        "status": scan.status,
        "cloud_account_id": scan.cloud_account_id,
        "note": (
            "Counts represent findings emitted by rules tagged to each "
            "framework. They are not compliance percentages or pass/fail "
            "scores because CloudSentinel does not persist a complete "
            "control-execution inventory for this scan."
        ),
    }
