from datetime import datetime

from pydantic import BaseModel


class DashboardTopRisk(BaseModel):
    finding_id: int
    rule_id: str
    title: str
    severity: str
    risk_score: float
    risk_level: str
    provider: str
    region: str
    resource_type: str
    resource_id: str
    internet_exposed: bool = False
    sensitive_data: bool = False
    asset_criticality: int = 1
    priority_reason: str


class DashboardOverviewResponse(BaseModel):
    provider: str
    latest_scan_id: int | None
    latest_scan_status: str | None
    latest_scan_completed_at: datetime | None

    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    posture_score: float
    posture_grade: str
    average_risk_score: float
    max_risk_score: float
    affected_resource_count: int

    exposed_asset_count: int
    sensitive_asset_count: int
    attack_path_count: int

    risk_trend: list[dict]
    compliance: dict | None
    top_risks: list[DashboardTopRisk]
    remediation: dict
    data_quality_notes: list[str]
