from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    provider: Literal["aws"]
    cloud_account_id: int = Field(..., gt=0)


class ScanExecutionErrorResponse(BaseModel):
    id: int
    service: str
    error_type: str
    error_code: str | None
    message: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanResponse(BaseModel):
    progress: dict | None = None
    id: int
    cloud_account_id: int | None
    provider: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    attempt_count: int
    max_attempts: int
    created_at: datetime
    updated_at: datetime
    execution_errors: list[ScanExecutionErrorResponse] = Field(
        default_factory=list
    )

    model_config = ConfigDict(from_attributes=True)
