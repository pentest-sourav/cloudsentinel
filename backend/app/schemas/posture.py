from datetime import datetime

from pydantic import BaseModel


class PostureTrendPoint(BaseModel):
    scan_id: int
    cloud_account_id: int | None
    provider: str
    status: str
    completed_at: datetime | None

    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    risk_score_sum: float
    execution_error_count: int


class PostureTrendResponse(BaseModel):
    items: list[PostureTrendPoint]
    limit: int
    cloud_account_id: int | None
