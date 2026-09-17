from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


class ScanCreate(BaseModel):
    provider: Literal["aws", "azure"]


class ScanResponse(BaseModel):
    id: int
    provider: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None

    model_config = ConfigDict(from_attributes=True)
