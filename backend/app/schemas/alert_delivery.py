from datetime import datetime

from pydantic import BaseModel


class AlertDeliveryResponse(BaseModel):
    id: int
    policy_id: int
    event_key: str
    status: str
    attempts: int
    last_error: str | None
    delivered_at: datetime | None
    created_at: datetime
    updated_at: datetime
