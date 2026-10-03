from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from backend.app.api.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)
from backend.app.services.auth_service import (
    authenticate_user,
    create_user_access_token,
    register_user,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    registration: RegisterRequest,
    db: Session = Depends(get_db),
    request: Request = None,
):
    try:
        return register_user(
            db=db,
            registration=registration,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc


@router.post(
    "/login",
    response_model=TokenResponse,
)
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db),
):
    user = authenticate_user(
        db=db,
        email=login_data.email,
        password=login_data.password,
        tenant_name=login_data.tenant_name,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_user_access_token(user)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
def current_user(
    current_user=Depends(get_current_user),
):
    return current_user
