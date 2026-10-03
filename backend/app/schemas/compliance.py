from pydantic import BaseModel


class ComplianceFrameworkSummary(BaseModel):
    framework: str
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    affected_rules: int
    affected_resources: int


class CompliancePostureResponse(BaseModel):
    items: list[ComplianceFrameworkSummary]
    scan_id: int
    status: str
    cloud_account_id: int | None
    note: str
