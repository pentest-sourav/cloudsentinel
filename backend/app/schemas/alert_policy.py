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


class AlertPolicyUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=3, max_length=100)
    endpoint_url: HttpUrl | None = None
    min_severity: Severity | None = None
    events: list[EventType] | None = None
    secret: str | None = Field(default=None, min_length=16, max_length=512)
    rotate_secret: bool = False
    enabled: bool | None = None

    @field_validator("events")
    @classmethod
    def validate_events(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized = sorted(set(value))
        if not normalized:
            raise ValueError("At least one alert event is required.")
        return normalized
