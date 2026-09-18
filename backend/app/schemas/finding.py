from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    rule_id: str
    title: str
    severity: str
    risk_score: float
    risk_level: str
    provider: str
    resource_type: str
    resource_id: str
    description: str
    evidence: dict
    remediation: str
    compliance: list
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingListResponse(BaseModel):
    items: list[FindingResponse]
    total: int
    limit: int
    offset: int
