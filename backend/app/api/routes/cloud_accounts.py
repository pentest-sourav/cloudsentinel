from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.core.database import get_db
from backend.app.schemas.cloud_account import (
    CloudAccountCreate,
    CloudAccountResponse,
)
from backend.app.services.cloud_account_service import (
    create_cloud_account,
    get_cloud_accounts,
    get_cloud_account,
)


router = APIRouter(
    prefix="/api/v1/cloud-accounts",
    tags=["Cloud Accounts"],
)


@router.post(
    "",
    response_model=CloudAccountResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_cloud_account(
    account_data: CloudAccountCreate,
    db: Session = Depends(get_db),
):
    return create_cloud_account(db, account_data)


@router.get(
    "",
    response_model=list[CloudAccountResponse],
)
def list_cloud_accounts(
    db: Session = Depends(get_db),
):
    return get_cloud_accounts(db)


@router.get(
    "/{account_id}",
    response_model=CloudAccountResponse,
)
def get_cloud_account_by_id(
    account_id: int,
    db: Session = Depends(get_db),
):
    account = get_cloud_account(db, account_id)

    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud account not found",
        )

    return account
