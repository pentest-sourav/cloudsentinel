from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    provider: Literal["aws", "azure"]
    cloud_account_id: int | None = None


class ScanExecutionErrorResponse(BaseModel):
    id: int
    service: str
    error_type: str
    error_code: str | None
    message: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanResponse(BaseModel):
    id: int
    cloud_account_id: int | None
    provider: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    execution_errors: list[ScanExecutionErrorResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
