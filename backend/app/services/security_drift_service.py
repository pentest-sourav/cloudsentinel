from __future__ import annotations

from sqlalchemy import tuple_
from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.scan import Scan
from backend.app.services.finding_lifecycle_service import FindingIdentity, build_finding_identity
from backend.app.services.scan_execution_error_service import get_execution_errors
from backend.app.services.scan_summary_service import build_risk_posture

TERMINAL = ("completed", "completed_with_warnings")
MAX_CHANGES = 50

def _scans(db: Session, tenant_id: int, cloud_account_id: int | None):
    q = db.query(Scan).filter(
        Scan.tenant_id == tenant_id,
        Scan.provider == "aws",
        Scan.status.in_(TERMINAL),
        Scan.completed_at.is_not(None),
    )
    if cloud_account_id is not None:
        q = q.filter(Scan.cloud_account_id == cloud_account_id)
        return q.order_by(Scan.completed_at.desc(), Scan.id.desc()).limit(2).all()

    latest = q.order_by(Scan.completed_at.desc(), Scan.id.desc()).first()
    if latest is None:
        return []

    previous_q = q.filter(Scan.id != latest.id)
    if latest.cloud_account_id is None:
        previous_q = previous_q.filter(Scan.cloud_account_id.is_(None))
    else:
        previous_q = previous_q.filter(Scan.cloud_account_id == latest.cloud_account_id)

    previous = previous_q.order_by(
        Scan.completed_at.desc(),
        Scan.id.desc(),
    ).first()
    return [latest, previous] if previous is not None else [latest]

def _findings(db: Session, scan_id: int):
    return db.query(Finding).filter(Finding.scan_id == scan_id).order_by(Finding.id.asc()).all()

def _signal(finding: Finding | None, key: str) -> bool:
    return bool(finding and (finding.evidence or {}).get(key, False))

def _exposed(finding: Finding | None) -> bool:
    return _signal(finding, "internet_exposed") or _signal(finding, "public_access_signal")

def _payload(current, previous, status, first_seen, last_seen):
    source = current or previous
    return {
        "fingerprint": build_finding_identity(source).fingerprint,
        "finding_id": current.id if current else None,
        "rule_id": source.rule_id,
        "title": source.title,
        "severity": current.severity if current else source.severity,
        "previous_severity": previous.severity if previous else None,
        "risk_score": float(current.risk_score) if current else 0.0,
        "previous_risk_score": float(previous.risk_score) if previous else None,
        "risk_delta": round(float(current.risk_score) - float(previous.risk_score), 2) if current and previous else round(float(current.risk_score) if current else 0.0, 2),
        "resource_type": source.resource_type,
        "resource_id": source.resource_id,
        "region": source.region,
        "status": status,
        "internet_exposed": _exposed(current),
        "previous_internet_exposed": _exposed(previous),
        "sensitive_data": _signal(current, "sensitive_data"),
        "previous_sensitive_data": _signal(previous, "sensitive_data"),
        "first_seen_scan_id": first_seen,
        "last_seen_scan_id": last_seen,
    }

def _first_seen(db, tenant_id, account_id, current_scan, identities):
    if not identities:
        return {}
    q = db.query(
        Finding.provider, Finding.rule_id, Finding.resource_type,
        Finding.resource_id, Finding.scan_id
    ).join(Scan, Scan.id == Finding.scan_id).filter(
        Scan.tenant_id == tenant_id,
        Scan.provider == "aws",
        Scan.status.in_(TERMINAL),
        Scan.completed_at.is_not(None),
        Scan.completed_at < current_scan.completed_at,
    )
    comparison_account_id = current_scan.cloud_account_id
    if comparison_account_id is None:
        q = q.filter(Scan.cloud_account_id.is_(None))
    else:
        q = q.filter(Scan.cloud_account_id == comparison_account_id)
    requested = list(identities)
    q = q.filter(
        tuple_(
            Finding.provider,
            Finding.rule_id,
            Finding.resource_type,
            Finding.resource_id,
        ).in_([
            (i.provider, i.rule_id, i.resource_type, i.resource_id)
            for i in requested
        ])
    )
    rows = q.order_by(Scan.completed_at.asc(), Scan.id.asc(), Finding.id.asc()).all()
    result = {}
    for row in rows:
        identity = FindingIdentity(row.provider, row.rule_id, row.resource_type, row.resource_id)
        if identity in identities and identity not in result:
            result[identity] = row.scan_id
    return result

def get_security_drift(*, db: Session, tenant_id: int, cloud_account_id: int | None = None) -> dict:
    scans = _scans(db, tenant_id, cloud_account_id)
    empty = {
        "provider": "aws", "cloud_account_id": cloud_account_id,
        "current_scan_id": None, "previous_scan_id": None,
        "current_completed_at": None, "previous_completed_at": None,
        "baseline_available": False, "posture_score": None,
        "previous_posture_score": None, "posture_delta": None,
        "drift_state": "no_data", "new_count": 0, "resolved_count": 0,
        "persistent_count": 0, "reopened_count": 0, "risk_increase_count": 0,
        "risk_decrease_count": 0, "newly_exposed_count": 0,
        "newly_sensitive_count": 0, "top_regressions": [], "top_improvements": [],
        "data_quality_notes": ["No completed AWS scans are available for drift comparison."],
    }
    if not scans:
        return empty

    current = scans[0]
    previous = scans[1] if len(scans) > 1 else None
    cf = {build_finding_identity(f): f for f in _findings(db, current.id)}
    pf = {build_finding_identity(f): f for f in _findings(db, previous.id)} if previous else {}
    ci, pi = set(cf), set(pf)
    new_ids, resolved_ids, persistent_ids = ci-pi, pi-ci, ci&pi

    first_seen = _first_seen(db, tenant_id, cloud_account_id, current, new_ids)
    reopened_ids = set(first_seen)
    new_only = new_ids - reopened_ids

    persistent = [_payload(cf[i], pf[i], "persistent", previous.id, current.id) for i in persistent_ids]
    new_changes = [_payload(cf[i], None, "new", current.id, current.id) for i in new_only]
    reopened = [_payload(cf[i], None, "reopened", first_seen[i], current.id) for i in reopened_ids]
    resolved = [_payload(None, pf[i], "resolved", previous.id, previous.id) for i in resolved_ids]

    risk_up = [x for x in persistent if x["risk_delta"] > 0 or (x["severity"] != x["previous_severity"] and x["severity"] in {"critical","high"})]
    risk_down = [x for x in persistent if x["risk_delta"] < 0 or (x["severity"] != x["previous_severity"] and x["previous_severity"] in {"critical","high"} and x["severity"] not in {"critical","high"})]
    exposed = [
        x for x in [*persistent, *new_changes, *reopened]
        if x["internet_exposed"] and not x["previous_internet_exposed"]
    ]
    sensitive = [
        x for x in [*persistent, *new_changes, *reopened]
        if x["sensitive_data"] and not x["previous_sensitive_data"]
    ]

    cp = build_risk_posture(db, current.id)
    pp = build_risk_posture(db, previous.id) if previous else None
    score = cp["score"]
    old_score = pp["score"] if pp else None
    delta = round(score-old_score, 1) if old_score is not None else None

    if not previous: state = "baseline"
    elif delta is not None and delta <= -1: state = "worsened"
    elif delta is not None and delta >= 1: state = "improved"
    elif len(risk_up) > len(risk_down) or len(new_changes)+len(reopened) > len(resolved): state = "worsened"
    elif len(risk_down) > len(risk_up) or len(resolved) > len(new_changes)+len(reopened): state = "improved"
    else: state = "stable"

    notes = []
    ce = get_execution_errors(db=db, scan_id=current.id)
    if ce: notes.append(f"{len(ce)} scanner execution error(s) affected the current comparison.")
    if previous:
        pe = get_execution_errors(db=db, scan_id=previous.id)
        if pe: notes.append(f"{len(pe)} scanner execution error(s) affected the baseline scan.")
    if current.status == "completed_with_warnings": notes.append("Current scan completed with warnings; drift may be incomplete.")
    if previous and previous.status == "completed_with_warnings": notes.append("Baseline scan completed with warnings; resolved/new counts may be incomplete.")

    regressions = sorted([*risk_up, *new_changes, *reopened, *exposed, *sensitive], key=lambda x:(x["risk_delta"],x["risk_score"]), reverse=True)
    improvements = sorted([*risk_down, *resolved], key=lambda x:(x["risk_delta"],-x["risk_score"]))

    return {
        "provider":"aws", "cloud_account_id":cloud_account_id,
        "current_scan_id":current.id, "previous_scan_id":previous.id if previous else None,
        "current_completed_at":current.completed_at, "previous_completed_at":previous.completed_at if previous else None,
        "baseline_available":previous is not None, "posture_score":score,
        "previous_posture_score":old_score, "posture_delta":delta, "drift_state":state,
        "new_count":len(new_only), "resolved_count":len(resolved_ids),
        "persistent_count":len(persistent_ids), "reopened_count":len(reopened_ids),
        "risk_increase_count":len(risk_up), "risk_decrease_count":len(risk_down),
        "newly_exposed_count":len(exposed), "newly_sensitive_count":len(sensitive),
        "top_regressions":regressions[:MAX_CHANGES], "top_improvements":improvements[:MAX_CHANGES],
        "data_quality_notes":notes,
    }
