import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


AWS_ROLE_ARN_PATTERN = (
    r"^arn:aws:iam::[0-9]{12}:role/"
    r"[A-Za-z0-9+=,.@_-]"
    r"[A-Za-z0-9+=,.@_/-]*$"
)


class CloudAccountCreate(BaseModel):
    name: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    # Azure is not implemented by the current scanner/orchestrator.
    provider: Literal["aws"]

    external_account_id: str = Field(
        ...,
        min_length=12,
        max_length=12,
        pattern=r"^[0-9]{12}$",
    )

    role_arn: str = Field(
        ...,
        min_length=1,
        max_length=2048,
    )

    region: str | None = Field(
        default=None,
        max_length=100,
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("name must not be blank")

        return value

    @field_validator("role_arn")
    @classmethod
    def validate_role_arn(cls, value: str) -> str:
        value = value.strip()

        if not re.fullmatch(AWS_ROLE_ARN_PATTERN, value):
            raise ValueError(
                "role_arn must be a valid AWS IAM role ARN"
            )

        return value

    @field_validator("region")
    @classmethod
    def validate_region(cls, value: str | None) -> str | None:
        if value is None:
            return None

        value = value.strip()

        return value or None


class CloudAccountResponse(BaseModel):
    id: int
    name: str
    provider: str
    external_account_id: str | None
    role_arn: str | None
    region: str | None
    status: str
    last_connection_at: datetime | None
    last_connection_error: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True,
    }


class CloudAccountConnectionResponse(BaseModel):
    account_id: int
    provider: str
    external_account_id: str
    role_arn: str
    region: str | None
    external_id: str
    principal_arn: str | None
    status: str
    last_connection_at: datetime | None
    last_connection_error: str | None


class CloudAccountConnectionTestResponse(BaseModel):
    account_id: int
    status: str
    connected: bool
    expected_account_id: str
    actual_account_id: str | None
    assumed_role_arn: str | None
    message: str
    tested_at: datetime
