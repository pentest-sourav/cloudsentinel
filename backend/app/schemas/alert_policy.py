from typing import Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator

Severity = Literal["critical", "high", "medium", "low", "info"]
EventType = Literal["new", "reopened"]


class AlertPolicyRequest(BaseModel):
    name: str = Field(min_length=3, max_length=100)
    endpoint_url: HttpUrl
    min_severity: Severity = "high"
    events: list[EventType] = Field(default_factory=lambda: ["new", "reopened"])
    secret: str | None = Field(default=None, min_length=16, max_length=512)
    enabled: bool = True

    @field_validator("events")
    @classmethod
    def validate_events(cls, value: list[str]) -> list[str]:
        normalized = sorted(set(value))
        if not normalized:
            raise ValueError("At least one alert event is required.")
        return normalized
