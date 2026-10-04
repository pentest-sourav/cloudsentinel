from datetime import datetime
from pydantic import BaseModel

class DriftFindingChange(BaseModel):
    fingerprint: str
    finding_id: int | None
    rule_id: str
    title: str
    severity: str
    previous_severity: str | None
    risk_score: float
    previous_risk_score: float | None
    risk_delta: float
    resource_type: str
    resource_id: str
    region: str
    status: str
    internet_exposed: bool
    previous_internet_exposed: bool
    sensitive_data: bool
    previous_sensitive_data: bool
    first_seen_scan_id: int
    last_seen_scan_id: int

class SecurityDriftResponse(BaseModel):
    provider: str
    cloud_account_id: int | None
    current_scan_id: int | None
    previous_scan_id: int | None
    current_completed_at: datetime | None
    previous_completed_at: datetime | None
    baseline_available: bool
    posture_score: float | None
    previous_posture_score: float | None
    posture_delta: float | None
    drift_state: str
    new_count: int
    resolved_count: int
    persistent_count: int
    reopened_count: int
    risk_increase_count: int
    risk_decrease_count: int
    newly_exposed_count: int
    newly_sensitive_count: int
    top_regressions: list[DriftFindingChange]
    top_improvements: list[DriftFindingChange]
    data_quality_notes: list[str]
