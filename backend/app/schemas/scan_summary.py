from datetime import datetime

from pydantic import BaseModel


class ScanExecutionErrorSummary(BaseModel):
    id: int
    service: str
    error_type: str
    error_code: str | None
    message: str
    created_at: datetime


class ScanProgressResponse(BaseModel):
    completed: int
    total: int
    percent: float
    service: str
    region: str


class ScanSummaryResponse(BaseModel):
    scan_id: int
    provider: str
    status: str

    total_findings: int

    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    execution_error_count: int
    execution_errors: list[ScanExecutionErrorSummary]
    progress: ScanProgressResponse | None = None
    risk_posture: RiskPostureSummary


class TopRiskFinding(BaseModel):
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


class RiskPostureSummary(BaseModel):
    score: float
    grade: str
    average_risk_score: float
    max_risk_score: float
    risk_score_sum: float
    affected_resource_count: int
    top_risks: list[TopRiskFinding]
