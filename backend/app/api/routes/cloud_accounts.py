from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
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
    current_user: User = Depends(get_current_user),
):
    return create_cloud_account(
        db=db,
        account_data=account_data,
        tenant_id=current_user.tenant_id,
    )


@router.get(
    "",
    response_model=list[CloudAccountResponse],
)
def list_cloud_accounts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return get_cloud_accounts(
        db=db,
        tenant_id=current_user.tenant_id,
    )


@router.get(
    "/{account_id}",
    response_model=CloudAccountResponse,
)
def get_cloud_account_by_id(
    account_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    account = get_cloud_account(
        db=db,
        account_id=account_id,
        tenant_id=current_user.tenant_id,
    )

    if account is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud account not found",
        )

    return account
