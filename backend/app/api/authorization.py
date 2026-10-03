from fastapi import Depends, HTTPException, status

from backend.app.api.dependencies import get_current_user
from backend.app.models.user import User


ROLE_OWNER = "owner"
ROLE_ADMINISTRATOR = "administrator"
ROLE_OPERATOR = "operator"
ROLE_VIEWER = "viewer"


def require_roles(*allowed_roles: str):
    allowed = frozenset(allowed_roles)

    if not allowed:
        raise ValueError("At least one allowed role is required.")

    def dependency(
        current_user: User = Depends(get_current_user),
    ) -> User:
        if current_user.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions.",
            )

        return current_user

    return dependency
