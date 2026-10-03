from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

class ScanScheduleCreate(BaseModel):
    cloud_account_id: int = Field(..., gt=0)
    interval_minutes: int = Field(..., ge=15, le=10080)

class ScanScheduleUpdate(BaseModel):
    enabled: bool

class ScanScheduleResponse(BaseModel):
    id: int
    cloud_account_id: int
    provider: str
    interval_minutes: int
    enabled: bool
    next_run_at: datetime
    last_run_at: datetime | None
    last_scan_id: int | None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(from_attributes=True)
