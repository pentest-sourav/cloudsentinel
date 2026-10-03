from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.finding_workflow import FindingWorkflow
from backend.app.models.scan import Scan
from backend.app.services.finding_lifecycle_service import build_finding_identity


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


_SLA_HOURS = {
    "critical": 24,
    "high": 72,
    "medium": 168,
    "low": 720,
    "info": 720,
}


def _sla_hours(finding: Finding) -> int:
    severity = finding.severity.lower()
    if severity in _SLA_HOURS:
        return _SLA_HOURS[severity]

    if finding.risk_score >= 9:
        return 24
    if finding.risk_score >= 7:
        return 72
    if finding.risk_score >= 5:
        return 168
    return 720


def _priority_reason(finding: Finding) -> str:
    evidence = finding.evidence or {}
    signals = []

    if finding.risk_score >= 9:
        signals.append("critical risk")
    elif finding.risk_score >= 7:
        signals.append("high risk")

    if evidence.get("internet_exposed") or evidence.get("public_access_signal"):
        signals.append("internet exposed")

    if evidence.get("sensitive_data"):
        signals.append("sensitive-data signal")

    if int(evidence.get("asset_criticality", 1) or 1) >= 4:
        signals.append("high asset criticality")

    return (
        " + ".join(signals).capitalize() + "."
        if signals
        else "Risk score indicates remediation attention."
    )


def _workflow_map(
    db: Session,
    *,
    tenant_id: int,
    scan: Scan,
    findings: list[Finding],
) -> dict[str, FindingWorkflow]:
    if not findings or scan.cloud_account_id is None:
        return {}

    fingerprints = [
        build_finding_identity(finding).fingerprint
        for finding in findings
    ]

    workflows = (
        db.query(FindingWorkflow)
        .filter(
            FindingWorkflow.tenant_id == tenant_id,
            FindingWorkflow.cloud_account_id == scan.cloud_account_id,
            FindingWorkflow.fingerprint.in_(fingerprints),
        )
        .all()
    )

    return {
        workflow.fingerprint: workflow
        for workflow in workflows
    }


def _queue_item(
    *,
    finding: Finding,
    workflow: FindingWorkflow | None,
    now: datetime,
) -> dict:
    sla_hours = _sla_hours(finding)
    recommended_due_at = _utc(finding.created_at) + timedelta(hours=sla_hours)

    due_at = _utc(workflow.due_at) if workflow and workflow.due_at else None

    if due_at is None:
        sla_state = "unconfigured"
        overdue_seconds = 0
    elif due_at <= now and workflow.status not in {
        "resolved",
        "accepted_risk",
    }:
        sla_state = "overdue"
        overdue_seconds = max(
            0,
            int((now - due_at).total_seconds()),
        )
    else:
        sla_state = "on_track"
        overdue_seconds = 0

    if workflow is None:
        workflow_status = "open"
        assignee_user_id = None
    else:
        workflow_status = workflow.status
        assignee_user_id = workflow.assignee_user_id

    return {
        "finding_id": finding.id,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
        "resource_type": finding.resource_type,
        "resource_id": finding.resource_id,
        "region": finding.region,
        "workflow_status": workflow_status,
        "assignee_user_id": assignee_user_id,
        "due_at": due_at,
        "recommended_due_at": recommended_due_at,
        "sla_target_hours": sla_hours,
        "sla_state": sla_state,
        "overdue_seconds": overdue_seconds,
        "priority_reason": _priority_reason(finding),
    }


def get_remediation_queue(
    *,
    db: Session,
    tenant_id: int,
    cloud_account_id: int | None = None,
    limit: int = 100,
) -> dict:
    query = (
        db.query(Scan)
        .filter(
            Scan.tenant_id == tenant_id,
            Scan.provider == "aws",
            Scan.status.in_(("completed", "completed_with_warnings")),
        )
    )

    if cloud_account_id is not None:
        query = query.filter(
            Scan.cloud_account_id == cloud_account_id,
        )

    scan = (
        query.order_by(
            Scan.completed_at.desc(),
            Scan.id.desc(),
        )
        .first()
    )

    if scan is None:
        return {
            "scan_id": None,
            "scan_status": None,
            "total_items": 0,
            "open_items": 0,
            "overdue_items": 0,
            "unassigned_items": 0,
            "items": [],
        }

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan.id)
        .order_by(
            Finding.risk_score.desc(),
            Finding.id.asc(),
        )
        .limit(limit)
        .all()
    )

    workflows = _workflow_map(
        db,
        tenant_id=tenant_id,
        scan=scan,
        findings=findings,
    )

    now = datetime.now(timezone.utc)
    items = [
        _queue_item(
            finding=finding,
            workflow=workflows.get(
                build_finding_identity(finding).fingerprint
            ),
            now=now,
        )
        for finding in findings
    ]

    active_items = [
        item
        for item in items
        if item["workflow_status"] not in {
            "resolved",
            "accepted_risk",
        }
    ]

    active_items.sort(
        key=lambda item: (
            item["sla_state"] != "overdue",
            -item["risk_score"],
            item["finding_id"],
        )
    )

    return {
        "scan_id": scan.id,
        "scan_status": scan.status,
        "total_items": len(active_items),
        "open_items": sum(
            1
            for item in active_items
            if item["workflow_status"] in {"open", "acknowledged", "in_progress"}
        ),
        "overdue_items": sum(
            1
            for item in active_items
            if item["sla_state"] == "overdue"
        ),
        "unassigned_items": sum(
            1
            for item in active_items
            if item["assignee_user_id"] is None
        ),
        "items": active_items,
    }
