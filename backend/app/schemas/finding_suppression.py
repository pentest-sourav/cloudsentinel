from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FindingSuppressionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=1000)
    expires_at: datetime | None = None

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 3:
            raise ValueError("Suppression reason must contain at least 3 characters.")
        return normalized


class FindingSuppressionResponse(BaseModel):
    id: int | None
    finding_id: int
    fingerprint: str
    suppressed: bool
    reason: str | None
    expires_at: datetime | None
    created_by_user_id: int | None
    created_at: datetime | None
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)
