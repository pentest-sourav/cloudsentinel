from unittest.mock import patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.authorization import (
    ROLE_ADMINISTRATOR,
    ROLE_OPERATOR,
    ROLE_OWNER,
    ROLE_VIEWER,
    require_roles,
)
from backend.app.core.database import Base, get_db
from backend.app.core.security import hash_password
from backend.app.main import app
from backend.app.models.cloud_account import CloudAccount
from backend.app.models.tenant import Tenant
from backend.app.models.user import User


PASSWORD = "StrongPassword-2026!"


@pytest.fixture()
def test_environment():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    TestSession = sessionmaker(bind=engine)

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    app.state.testing = True

    with TestClient(app) as client:
        yield client, TestSession

    app.dependency_overrides.clear()
    app.state.testing = False
    engine.dispose()


def test_require_roles_allows_authorized_role():
    user = User(role=ROLE_OWNER)
    dependency = require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR)

    assert dependency(user) is user


def test_require_roles_rejects_unauthorized_role():
    user = User(role=ROLE_VIEWER)
    dependency = require_roles(ROLE_OWNER, ROLE_ADMINISTRATOR)

    with pytest.raises(HTTPException) as exc_info:
        dependency(user)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "Insufficient permissions."


def _create_owner_and_account(SessionLocal):
    db = SessionLocal()

    tenant = Tenant(
        name="Authorization Tenant",
        slug="authorization-tenant",
        status="active",
    )
    db.add(tenant)
    db.flush()

    user = User(
        tenant_id=tenant.id,
        email="authorization@example.com",
        password_hash=hash_password(PASSWORD),
        full_name="Authorization User",
        role=ROLE_OWNER,
        is_active=True,
    )
    db.add(user)
    db.flush()

    account = CloudAccount(
        tenant_id=tenant.id,
        name="Authorization AWS Account",
        provider="aws",
        external_account_id="123456789012",
        role_arn=(
            "arn:aws:iam::123456789012:"
            "role/CloudSentinelReadOnly"
        ),
        external_id="cs-authorization-test",
        region="ap-south-1",
        status="connected",
    )
    db.add(account)
    db.commit()
    db.refresh(user)
    db.refresh(account)
    db.close()

    return user.id, account.id


def _token(client, email="authorization@example.com"):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": PASSWORD,
            "tenant_name": "Authorization Tenant",
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_viewer_cannot_create_scan(test_environment):
    client, SessionLocal = test_environment
    user_id, account_id = _create_owner_and_account(SessionLocal)

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).one()
        user.role = ROLE_VIEWER
        db.commit()
    finally:
        db.close()

    token = _token(client)

    with patch(
        "backend.app.api.routes.scans.ScanQueue",
    ) as queue:
        response = client.post(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "provider": "aws",
                "cloud_account_id": account_id,
            },
        )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions."
    queue.assert_not_called()


def test_operator_can_create_scan(test_environment):
    client, SessionLocal = test_environment
    user_id, account_id = _create_owner_and_account(SessionLocal)

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).one()
        user.role = ROLE_OPERATOR
        db.commit()
    finally:
        db.close()

    token = _token(client)

    with patch(
        "backend.app.api.routes.scans.ScanQueue",
    ) as queue_class:
        queue = queue_class.return_value
        queue.enqueue.return_value = "1-0"

        response = client.post(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "provider": "aws",
                "cloud_account_id": account_id,
            },
        )

    assert response.status_code == 201
    queue.enqueue.assert_called_once()


def test_viewer_cannot_delete_cloud_account(test_environment):
    client, SessionLocal = test_environment
    user_id, account_id = _create_owner_and_account(SessionLocal)

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).one()
        user.role = ROLE_VIEWER
        db.commit()
    finally:
        db.close()

    token = _token(client)

    response = client.delete(
        f"/api/v1/cloud-accounts/{account_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions."


def test_viewer_can_read_cloud_account(test_environment):
    client, SessionLocal = test_environment
    user_id, account_id = _create_owner_and_account(SessionLocal)

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).one()
        user.role = ROLE_VIEWER
        db.commit()
    finally:
        db.close()

    token = _token(client)

    response = client.get(
        f"/api/v1/cloud-accounts/{account_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == account_id
