from datetime import datetime

from pydantic import BaseModel


class ScanExecutionErrorSummary(BaseModel):
    id: int
    service: str
    error_type: str
    error_code: str | None
    message: str
    created_at: datetime


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
