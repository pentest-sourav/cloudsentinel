from sqlalchemy.orm import Session

from backend.app.models.cloud_account import CloudAccount
from backend.app.schemas.cloud_account import CloudAccountCreate


def create_cloud_account(
    db: Session,
    account_data: CloudAccountCreate,
    tenant_id: int,
) -> CloudAccount:
    account = CloudAccount(
        tenant_id=tenant_id,
        name=account_data.name,
        provider=account_data.provider,
        external_account_id=account_data.external_account_id,
        role_arn=account_data.role_arn,
        external_id=account_data.external_id,
        region=account_data.region,
        status="active",
    )

    db.add(account)
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
