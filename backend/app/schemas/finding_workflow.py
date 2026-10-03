from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class FindingWorkflowRequest(BaseModel):
    status: str = "open"
    assignee_user_id: int | None = None
    due_at: datetime | None = None
    note: str | None = Field(default=None, max_length=2000)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"open", "acknowledged", "in_progress", "resolved", "accepted_risk"}:
            raise ValueError("status must be open, acknowledged, in_progress, resolved, or accepted_risk.")
        return normalized

    @field_validator("note")
    @classmethod
    def validate_note(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class FindingWorkflowResponse(BaseModel):
    id: int | None
    finding_id: int
    fingerprint: str
    status: str
    assignee_user_id: int | None
    due_at: datetime | None
    note: str | None
    updated_by_user_id: int | None
    created_at: datetime | None
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)
