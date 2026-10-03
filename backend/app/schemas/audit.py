from datetime import datetime

from pydantic import BaseModel


class AuditEventResponse(BaseModel):
    id: int
    tenant_id: int | None
    user_id: int | None
    action: str
    status: str
    resource_type: str | None
    resource_id: str | None
    request_id: str | None
    ip_address: str | None
    metadata: dict
    created_at: datetime

    model_config = {
        "from_attributes": True,
    }


class AuditEventListResponse(BaseModel):
    items: list[AuditEventResponse]
    total: int
    limit: int
    offset: int
