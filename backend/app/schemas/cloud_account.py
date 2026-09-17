from pydantic import BaseModel, Field
from typing import Literal


class CloudAccountCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    provider: Literal["aws", "azure"]
    external_account_id: str | None = Field(
        default=None,
        max_length=100,
    )


class CloudAccountResponse(BaseModel):
    id: int
    name: str
    provider: str
    external_account_id: str | None
    status: str

    model_config = {
        "from_attributes": True
    }
