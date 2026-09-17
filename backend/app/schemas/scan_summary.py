from pydantic import BaseModel


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
