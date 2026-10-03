from hashlib import sha256

from fastapi import APIRouter, Depends, HTTPException, Request, status

from backend.app.core.config import settings
from backend.app.core.rate_limit import rate_limiter
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
from backend.app.services.audit_service import (
    AUDIT_FAILURE,
    AUDIT_SUCCESS,
    safe_record_audit_event,
)


router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)


def _audit_email_fingerprint(email: str) -> str:
    """Return a non-reversible correlation key for authentication telemetry."""
    normalized = email.strip().lower()
    return sha256(
        f"cloudsentinel:audit-email:{settings.jwt_secret_key}:{normalized}".encode(
            "utf-8"
        )
    ).hexdigest()


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    registration: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        user = register_user(
            db=db,
            registration=registration,
        )
        safe_record_audit_event(
            db=db,
            action="auth.register",
            status=AUDIT_SUCCESS,
            tenant_id=user.tenant_id,
            user_id=user.id,
            request_id=getattr(request.state, "request_id", None),
            ip_address=request.client.host if request.client else None,
        )
        return user
    except ValueError as exc:
        safe_record_audit_event(
            db=db,
            action="auth.register",
            status=AUDIT_FAILURE,
            request_id=getattr(request.state, "request_id", None),
            ip_address=request.client.host if request.client else None,
            metadata={"reason": str(exc)[:200]},
        )
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
    request: Request,
    db: Session = Depends(get_db),
):
    account_decision = rate_limiter.check(
        request,
        scope="auth-login-account",
        identifier=login_data.email.strip().lower(),
        limit=settings.rate_limit_auth_account_max_requests,
        window_seconds=settings.rate_limit_window_seconds,
    )
    if not account_decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please retry later.",
            headers={"Retry-After": str(account_decision.retry_after)},
        )

    user = authenticate_user(
        db=db,
        email=login_data.email,
        password=login_data.password,
        tenant_name=login_data.tenant_name,
    )

    if user is None:
        safe_record_audit_event(
            db=db,
            action="auth.login",
            status=AUDIT_FAILURE,
            request_id=getattr(request.state, "request_id", None),
            ip_address=request.client.host if request.client else None,
            metadata={
                "email_fingerprint": _audit_email_fingerprint(login_data.email),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_user_access_token(user)

    safe_record_audit_event(
        db=db,
        action="auth.login",
        status=AUDIT_SUCCESS,
        tenant_id=user.tenant_id,
        user_id=user.id,
        request_id=getattr(request.state, "request_id", None),
        ip_address=request.client.host if request.client else None,
    )

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
