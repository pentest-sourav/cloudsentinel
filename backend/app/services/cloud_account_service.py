import secrets

from sqlalchemy.orm import Session

from backend.app.models.cloud_account import CloudAccount
from backend.app.schemas.cloud_account import CloudAccountCreate
from backend.app.services.cloud_account_status import (
    CLOUD_ACCOUNT_PENDING,
    CLOUD_ACCOUNT_CONNECTED,
    CLOUD_ACCOUNT_CONNECTION_FAILED,
    LEGACY_CONNECTED_STATUS,
    SCAN_ELIGIBLE_ACCOUNT_STATUSES,
)


def generate_external_id() -> str:
    return f"cs-{secrets.token_urlsafe(32)}"


def create_cloud_account(
    db: Session,
    account_data: CloudAccountCreate,
    tenant_id: int,
) -> CloudAccount:
    role_account_id = account_data.role_arn.split(":")[4]

    if role_account_id != account_data.external_account_id:
        raise ValueError(
            "AWS IAM role ARN account ID must match the AWS account ID."
        )

    duplicate = (
        db.query(CloudAccount)
        .filter(
            CloudAccount.tenant_id == tenant_id,
            CloudAccount.provider == account_data.provider,
            CloudAccount.external_account_id
            == account_data.external_account_id,
        )
        .first()
    )

    if duplicate is not None:
        raise ValueError(
            "This AWS account is already connected to this tenant."
        )

    account = CloudAccount(
        tenant_id=tenant_id,
        name=account_data.name,
        provider=account_data.provider,
        external_account_id=account_data.external_account_id,
        role_arn=account_data.role_arn,
        external_id=generate_external_id(),
        region=account_data.region,
        status=CLOUD_ACCOUNT_PENDING,
    )

    db.add(account)
    db.commit()
    db.refresh(account)

    return account


def rotate_external_id(
    db: Session,
    account: CloudAccount,
) -> CloudAccount:
    """Rotate the customer trust external ID and invalidate prior trust setup."""

    account.external_id = generate_external_id()
    account.status = CLOUD_ACCOUNT_PENDING
    account.last_connection_at = None
    account.last_connection_error = (
        "AWS external ID rotated. Update the customer IAM trust policy "
        "before reconnecting this account."
    )

    db.commit()
    db.refresh(account)

    return account


def get_cloud_accounts(
    db: Session,
    tenant_id: int,
) -> list[CloudAccount]:
    return (
        db.query(CloudAccount)
        .filter(CloudAccount.tenant_id == tenant_id)
        .order_by(CloudAccount.id.desc())
        .all()
    )


def get_cloud_account(
    db: Session,
    account_id: int,
    tenant_id: int,
) -> CloudAccount | None:
    return (
        db.query(CloudAccount)
        .filter(
            CloudAccount.id == account_id,
            CloudAccount.tenant_id == tenant_id,
        )
        .first()
    )


def clear_cloud_account_workspace(
    db: Session,
    tenant_id: int,
) -> int:
    accounts = (
        db.query(CloudAccount)
        .filter(CloudAccount.tenant_id == tenant_id)
        .all()
    )

    deleted_accounts = 0

    for account in accounts:
        # Keep historical scans when an account is removed. Their
        # cloud_account_id becomes NULL through the FK.
        db.delete(account)
        deleted_accounts += 1

    db.commit()

    return deleted_accounts


def delete_cloud_account(
    db: Session,
    account_id: int,
    tenant_id: int,
) -> bool:
    account = get_cloud_account(
        db=db,
        account_id=account_id,
        tenant_id=tenant_id,
    )

    if account is None:
        return False

    # Preserve historical scan records when an account configuration
    # is removed. The scan remains tenant-owned history, but its
    # cloud-account association is cleared because the account no
    # longer exists.
    from backend.app.models.scan import Scan

    (
        db.query(Scan)
        .filter(
            Scan.cloud_account_id == account.id,
            Scan.tenant_id == tenant_id,
        )
        .update(
            {Scan.cloud_account_id: None},
            synchronize_session=False,
        )
    )

    db.delete(account)
    db.commit()

    return True
