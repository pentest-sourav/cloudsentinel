from datetime import datetime

from pydantic import BaseModel


class ScanHistoryResponse(BaseModel):
    id: int
    provider: str
    status: str

    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None

    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int


class ScanHistoryListResponse(BaseModel):
    items: list[ScanHistoryResponse]
    total: int
    limit: int
    offset: int
