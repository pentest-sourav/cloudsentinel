from typing import Literal

from pydantic import BaseModel, Field


class CloudAccountCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    provider: Literal["aws", "azure"]
    external_account_id: str | None = Field(
        default=None,
        max_length=100,
    )
    role_arn: str | None = Field(
        default=None,
        max_length=2048,
    )
    external_id: str | None = Field(
        default=None,
        max_length=1024,
    )
    region: str | None = Field(
        default=None,
        max_length=100,
    )


class CloudAccountResponse(BaseModel):
    id: int
    name: str
    provider: str
    external_account_id: str | None
    role_arn: str | None
    region: str | None
    status: str

    model_config = {
        "from_attributes": True,
    }
