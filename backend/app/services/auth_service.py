from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from backend.app.models.tenant import Tenant
from backend.app.models.user import User
from backend.app.schemas.auth import RegisterRequest


ACTIVE_TENANT_STATUS = "active"


def _tenant_slug(value: str) -> str:
    return value.lower().strip().replace(" ", "-")


def register_user(
    db: Session,
    registration: RegisterRequest,
) -> User:
    email = registration.email.lower().strip()
    tenant_slug = _tenant_slug(registration.tenant_name)

    existing_tenant = (
        db.query(Tenant)
        .filter(Tenant.slug == tenant_slug)
        .first()
    )

    if existing_tenant is not None:
        raise ValueError(
            f"Tenant '{tenant_slug}' already exists."
        )

    tenant = Tenant(
        name=registration.tenant_name.strip(),
        slug=tenant_slug,
        status=ACTIVE_TENANT_STATUS,
    )

    db.add(tenant)

    try:
        # The application-level existence check above is only an
        # optimization. The database unique constraint remains the
        # authoritative concurrency guard for tenant slugs.
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            f"Tenant '{tenant_slug}' already exists."
        ) from exc

    existing_user = (
        db.query(User)
        .filter(
            User.tenant_id == tenant.id,
            User.email == email,
        )
        .first()
    )

    if existing_user is not None:
        db.rollback()
        raise ValueError(
            "A user with this email already exists."
        )

    user = User(
        tenant_id=tenant.id,
        email=email,
        password_hash=hash_password(registration.password),
        full_name=registration.full_name.strip(),
        role="owner",
        is_active=True,
    )

    db.add(user)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ValueError(
            "Registration could not be completed because the account "
            "conflicts with an existing record."
        ) from exc

    db.refresh(user)

    return user


def authenticate_user(
    db: Session,
    email: str,
    password: str,
    tenant_name: str | None = None,
) -> User | None:
    normalized_email = email.lower().strip()

    query = (
        db.query(User)
        .join(
            Tenant,
            Tenant.id == User.tenant_id,
        )
        .filter(
            User.email == normalized_email,
            User.is_active.is_(True),
            Tenant.status == ACTIVE_TENANT_STATUS,
        )
    )

    if tenant_name is not None:
        normalized_tenant_slug = _tenant_slug(tenant_name)

        query = query.filter(
            Tenant.slug == normalized_tenant_slug
        )

        user = query.first()
    else:
        # Email-only login is retained for compatibility only when
        # exactly one active user exists across active tenants.
        #
        # Never arbitrarily select one account when the same email
        # belongs to multiple tenants.
        matches = query.limit(2).all()

        if len(matches) != 1:
            return None

        user = matches[0]

    if user is None:
        return None

    if not verify_password(
        password,
        user.password_hash,
    ):
        return None

    return user


def create_user_access_token(user: User) -> tuple[str, int]:
    expires_minutes = settings.jwt_access_token_expire_minutes

    token = create_access_token(
        user_id=user.id,
        expires_minutes=expires_minutes,
    )

    return token, expires_minutes * 60
