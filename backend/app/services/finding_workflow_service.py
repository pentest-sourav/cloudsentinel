from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.app.models.finding import Finding
from backend.app.models.finding_workflow import FindingWorkflow
from backend.app.models.scan import Scan
from backend.app.models.user import User
from backend.app.services.finding_lifecycle_service import build_finding_identity


def _scope(
    db: Session,
    *,
    finding: Finding,
    tenant_id: int,
) -> tuple[Scan, str]:
    scan = db.query(Scan).filter(
        Scan.id == finding.scan_id,
        Scan.tenant_id == tenant_id,
    ).first()
    if scan is None or scan.cloud_account_id is None:
        raise ValueError("Finding is not associated with a cloud account.")
    return scan, build_finding_identity(finding).fingerprint


def get_workflow_for_finding(
    db: Session,
    *,
    finding: Finding,
    tenant_id: int,
) -> FindingWorkflow | None:
    scan, fingerprint = _scope(db, finding=finding, tenant_id=tenant_id)
    return db.query(FindingWorkflow).filter(
        FindingWorkflow.tenant_id == tenant_id,
        FindingWorkflow.cloud_account_id == scan.cloud_account_id,
        FindingWorkflow.fingerprint == fingerprint,
    ).first()


def upsert_workflow(
    db: Session,
    *,
    finding: Finding,
    tenant_id: int,
    user_id: int,
    status: str,
    assignee_user_id: int | None,
    due_at: datetime | None,
    note: str | None,
) -> FindingWorkflow:
    scan, fingerprint = _scope(db, finding=finding, tenant_id=tenant_id)

    if due_at is not None:
        if due_at.tzinfo is None:
            raise ValueError("due_at must include a timezone.")
        if due_at <= datetime.now(timezone.utc):
            raise ValueError("due_at must be in the future.")

    if assignee_user_id is not None:
        assignee = db.query(User).filter(
            User.id == assignee_user_id,
            User.tenant_id == tenant_id,
            User.is_active.is_(True),
        ).first()
        if assignee is None:
            raise ValueError("Assignee user not found in this tenant.")

    workflow = db.query(FindingWorkflow).filter(
        FindingWorkflow.tenant_id == tenant_id,
        FindingWorkflow.cloud_account_id == scan.cloud_account_id,
        FindingWorkflow.fingerprint == fingerprint,
    ).with_for_update().first()

    now = datetime.now(timezone.utc)
    if workflow is None:
        workflow = FindingWorkflow(
            tenant_id=tenant_id,
            cloud_account_id=scan.cloud_account_id,
            fingerprint=fingerprint,
            status=status,
            assignee_user_id=assignee_user_id,
            due_at=due_at,
            note=note,
            updated_by_user_id=user_id,
            created_at=now,
            updated_at=now,
        )
        db.add(workflow)
    else:
        workflow.status = status
        workflow.assignee_user_id = assignee_user_id
        workflow.due_at = due_at
        workflow.note = note
        workflow.updated_by_user_id = user_id
        workflow.updated_at = now

    db.commit()
    db.refresh(workflow)
    return workflow


def delete_workflow(
    db: Session,
    *,
    finding: Finding,
    tenant_id: int,
) -> bool:
    workflow = get_workflow_for_finding(
        db=db,
        finding=finding,
        tenant_id=tenant_id,
    )
    if workflow is None:
        return False
    db.delete(workflow)
    db.commit()
    return True


def workflow_response(
    *,
    finding: Finding,
    workflow: FindingWorkflow | None,
) -> dict:
    fingerprint = build_finding_identity(finding).fingerprint
    return {
        "id": workflow.id if workflow else None,
        "finding_id": finding.id,
        "fingerprint": fingerprint,
        "status": workflow.status if workflow else "open",
        "assignee_user_id": workflow.assignee_user_id if workflow else None,
        "due_at": workflow.due_at if workflow else None,
        "note": workflow.note if workflow else None,
        "updated_by_user_id": workflow.updated_by_user_id if workflow else None,
        "created_at": workflow.created_at if workflow else None,
        "updated_at": workflow.updated_at if workflow else None,
    }
