import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from sqlalchemy.orm import Session

from backend.app.models.cloud_account import CloudAccount

from backend.app.services.cloud_account_status import (
    CLOUD_ACCOUNT_PENDING,
    CLOUD_ACCOUNT_CONNECTED,
    CLOUD_ACCOUNT_CONNECTION_FAILED,
    LEGACY_CONNECTED_STATUS,
    SCAN_ELIGIBLE_ACCOUNT_STATUSES,
)
from scanner.aws.session import create_aws_session


@dataclass(frozen=True)
class ConnectionIdentity:
    account_id: str
    arn: str
    user_id: str | None = None


def generate_external_id() -> str:
    return f"cs-{secrets.token_urlsafe(32)}"


def get_cloudsentinel_principal_arn() -> str | None:
    configured = os.getenv(
        "CLOUDSENTINEL_AWS_PRINCIPAL_ARN"
    )

    if configured:
        return configured.strip()

    # Local-development fallback.
    try:
        identity = boto3.client("sts").get_caller_identity()
        arn = identity.get("Arn")

        return arn if arn else None

    except (ClientError, BotoCoreError):
        return None


def create_connection_external_id() -> str:
    return generate_external_id()


def get_connection_configuration(
    db: Session,
    account: CloudAccount,
) -> dict:
    external_id = account.external_id

    if not external_id:
        from backend.app.services.cloud_account_service import rotate_external_id
        account = rotate_external_id(
            db=db,
            account=account,
        )
        external_id = account.external_id

    return {
        "account_id": account.id,
        "provider": account.provider,
        "external_account_id": account.external_account_id,
        "role_arn": account.role_arn,
        "region": account.region,
        "external_id": external_id,
        "principal_arn": get_cloudsentinel_principal_arn(),
        "status": account.status,
        "last_connection_at": account.last_connection_at,
        "last_connection_error": account.last_connection_error,
    }


def mark_connection_success(
    db: Session,
    account: CloudAccount,
) -> CloudAccount:
    account.status = CLOUD_ACCOUNT_CONNECTED
    account.last_connection_at = datetime.now(timezone.utc)
    account.last_connection_error = None

    db.commit()
    db.refresh(account)

    return account


def mark_connection_failure(
    db: Session,
    account: CloudAccount,
    message: str,
) -> CloudAccount:
    account.status = CLOUD_ACCOUNT_CONNECTION_FAILED
    account.last_connection_error = message[:4000]

    db.commit()
    db.refresh(account)

    return account


def test_aws_connection(
    account: CloudAccount,
) -> ConnectionIdentity:
    if account.provider != "aws":
        raise RuntimeError(
            "Connection testing is currently supported for AWS accounts only."
        )

    if not account.role_arn:
        raise RuntimeError(
            "AWS IAM role ARN is not configured."
        )

    if not account.external_id:
        raise RuntimeError(
            "AWS external ID is not configured."
        )

    try:
        session = create_aws_session(
            role_arn=account.role_arn,
            external_id=account.external_id,
            region_name=account.region,
        )

        sts = session.client("sts")
        identity = sts.get_caller_identity()

        actual_account_id = identity.get("Account")
        actual_arn = identity.get("Arn")

        if actual_account_id != account.external_account_id:
            raise RuntimeError(
                "AWS account identity mismatch: the assumed role "
                "belongs to a different AWS account."
            )

        if not actual_account_id or not actual_arn:
            raise RuntimeError(
                "AWS STS returned an incomplete caller identity."
            )

        return ConnectionIdentity(
            account_id=actual_account_id,
            arn=actual_arn,
            user_id=identity.get("UserId"),
        )

    except RuntimeError:
        raise

    except ClientError as exc:
        error = exc.response.get("Error", {})
        code = error.get("Code", "UnknownError")
        message = error.get(
            "Message",
            "AWS connection test failed.",
        )

        raise RuntimeError(
            f"AWS connection failed: {code}: {message}"
        ) from exc

    except BotoCoreError as exc:
        raise RuntimeError(
            f"AWS SDK error during connection test: {exc}"
        ) from exc
