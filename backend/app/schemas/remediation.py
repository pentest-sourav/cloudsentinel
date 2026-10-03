from datetime import datetime

from pydantic import BaseModel


class RemediationQueueItem(BaseModel):
    finding_id: int
    rule_id: str
    title: str
    severity: str
    risk_score: float
    risk_level: str
    resource_type: str
    resource_id: str
    region: str
    workflow_status: str
    assignee_user_id: int | None
    due_at: datetime | None
    recommended_due_at: datetime
    sla_target_hours: int
    sla_state: str
    overdue_seconds: int
    priority_reason: str


class RemediationQueueResponse(BaseModel):
    scan_id: int | None
    scan_status: str | None
    total_items: int
    open_items: int
    overdue_items: int
    unassigned_items: int
    items: list[RemediationQueueItem]
