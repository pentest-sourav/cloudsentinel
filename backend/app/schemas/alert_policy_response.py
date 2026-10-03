from datetime import datetime

from pydantic import BaseModel


class AlertPolicyResponse(BaseModel):
    id: int
    name: str
    enabled: bool
    endpoint_url: str
    min_severity: str
    events: list[str]
    has_secret: bool
    created_at: datetime
    updated_at: datetime
