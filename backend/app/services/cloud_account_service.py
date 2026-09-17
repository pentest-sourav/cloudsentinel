from sqlalchemy.orm import Session

from backend.app.models.cloud_account import CloudAccount
from backend.app.schemas.cloud_account import CloudAccountCreate


def create_cloud_account(
    db: Session,
    account_data: CloudAccountCreate,
) -> CloudAccount:
    account = CloudAccount(
        name=account_data.name,
        provider=account_data.provider,
        external_account_id=account_data.external_account_id,
        status="active",
    )

    db.add(account)
    db.commit()
    db.refresh(account)

    return account

def get_cloud_accounts(db: Session) -> list[CloudAccount]:
    return db.query(CloudAccount).order_by(CloudAccount.id.desc()).all()

def get_cloud_account(
    db: Session,
    account_id: int,
) -> CloudAccount | None:
    return (
        db.query(CloudAccount)
        .filter(CloudAccount.id == account_id)
        .first()
    )
