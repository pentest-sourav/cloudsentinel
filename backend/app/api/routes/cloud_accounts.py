from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.api.authorization import (
    ROLE_ADMINISTRATOR,
    ROLE_OPERATOR,
    ROLE_OWNER,
    require_roles,
)
from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.schemas.cloud_account import (
    CloudAccountConnectionResponse,
    CloudAccountConnectionTestResponse,
    CloudAccountCreate,
    CloudAccountResponse,
)
from backend.app.services.cloud_account_connection_service import (
    get_connection_configuration,
    mark_connection_failure,
    mark_connection_success,
    test_aws_connection,
)
from backend.app.services.cloud_account_service import (
    create_cloud_account,
    delete_cloud_account,
    get_cloud_account,
    get_cloud_accounts,
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
    current_user: User = Depends(
        require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR),
    ),
):
    try:
        return create_cloud_account(
            db=db,
            account_data=account_data,
            tenant_id=current_user.tenant_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


@router.get(
    "",
    response_model=list[CloudAccountResponse],
)
def list_cloud_accounts(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            ROLE_OWNER,
            ROLE_ADMINISTRATOR,
            ROLE_OPERATOR,
        ),
    ),
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
    current_user: User = Depends(
        require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR),
    ),
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


@router.get(
    "/{account_id}/connection",
    response_model=CloudAccountConnectionResponse,
)
def get_cloud_account_connection(
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

    return get_connection_configuration(
        db=db,
        account=account,
    )


@router.post(
    "/{account_id}/test",
    response_model=CloudAccountConnectionTestResponse,
)
def test_cloud_account_connection(
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

    tested_at = datetime.now(timezone.utc)

    try:
        identity = test_aws_connection(account)

    except RuntimeError as exc:
        mark_connection_failure(
            db=db,
            account=account,
            message=str(exc),
        )

        return CloudAccountConnectionTestResponse(
            account_id=account.id,
            status=account.status,
            connected=False,
            expected_account_id=account.external_account_id or "",
            actual_account_id=None,
            assumed_role_arn=None,
            message=str(exc),
            tested_at=tested_at,
        )

    mark_connection_success(
        db=db,
        account=account,
    )

    return CloudAccountConnectionTestResponse(
        account_id=account.id,
        status=account.status,
        connected=True,
        expected_account_id=account.external_account_id or "",
        actual_account_id=identity.account_id,
        assumed_role_arn=identity.arn,
        message="AWS connection verified successfully.",
        tested_at=tested_at,
    )


@router.delete(
    "/{account_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_cloud_account(
    account_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    deleted = delete_cloud_account(
        db=db,
        account_id=account_id,
        tenant_id=current_user.tenant_id,
    )

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cloud account not found",
        )

    return None
