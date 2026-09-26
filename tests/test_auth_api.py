import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app
from backend.app.models.tenant import Tenant
from backend.app.models.user import User


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    Base.metadata.create_all(engine)

    TestSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    def override_get_db():
        db = TestSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
    engine.dispose()


def test_register_and_login(client):
    password = "StrongPassword-2026!"

    register_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "auth-integration@example.com",
            "password": password,
            "full_name": "Auth Integration User",
            "tenant_name": "Auth Integration Tenant",
        },
    )

    assert register_response.status_code == 201

    user = register_response.json()

    assert user["email"] == "auth-integration@example.com"
    assert user["role"] == "owner"
    assert user["is_active"] is True
    assert user["tenant_id"] is not None

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "auth-integration@example.com",
            "password": password,
            "tenant_name": "Auth Integration Tenant",
        },
    )

    assert login_response.status_code == 200

    token_data = login_response.json()

    assert token_data["access_token"]
    assert token_data["token_type"] == "bearer"
    assert token_data["expires_in"] > 0


def test_duplicate_tenant_registration_returns_conflict(client):
    password = "StrongPassword-2026!"

    first_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "first@example.com",
            "password": password,
            "full_name": "First User",
            "tenant_name": "Duplicate Tenant",
        },
    )

    assert first_response.status_code == 201

    second_response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "second@example.com",
            "password": password,
            "full_name": "Second User",
            "tenant_name": "Duplicate Tenant",
        },
    )

    assert second_response.status_code == 409


def test_invalid_password_returns_unauthorized(client):
    password = "StrongPassword-2026!"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "wrong-password@example.com",
            "password": password,
            "full_name": "Wrong Password User",
            "tenant_name": "Wrong Password Tenant",
        },
    )

    assert response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "wrong-password@example.com",
            "password": "WrongPassword-2026!",
            "tenant_name": "Wrong Password Tenant",
        },
    )

    assert login_response.status_code == 401
    assert login_response.json()["detail"] == "Invalid email or password."


def test_invalid_email_returns_unauthorized(client):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "does-not-exist@example.com",
            "password": "StrongPassword-2026!",
            "tenant_name": "Does Not Exist",
        },
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_invalid_registration_password_is_rejected(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "short-password@example.com",
            "password": "short",
            "full_name": "Short Password User",
            "tenant_name": "Short Password Tenant",
        },
    )

    assert response.status_code == 422


def test_same_email_can_exist_in_different_tenants_with_tenant_login(client):
    password = "StrongPassword-2026!"

    for tenant_name in ("Tenant Alpha", "Tenant Beta"):
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "shared@example.com",
                "password": password,
                "full_name": f"Shared User {tenant_name}",
                "tenant_name": tenant_name,
            },
        )
        assert response.status_code == 201

        login_response = client.post(
            "/api/v1/auth/login",
            json={
                "email": "shared@example.com",
                "password": password,
                "tenant_name": tenant_name,
            },
        )

        assert login_response.status_code == 200
        assert login_response.json()["access_token"]


def test_ambiguous_email_only_login_is_rejected(client):
    password = "StrongPassword-2026!"

    for tenant_name in ("Ambiguous Alpha", "Ambiguous Beta"):
        response = client.post(
            "/api/v1/auth/register",
            json={
                "email": "ambiguous@example.com",
                "password": password,
                "full_name": "Ambiguous User",
                "tenant_name": tenant_name,
            },
        )
        assert response.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "ambiguous@example.com",
            "password": password,
        },
    )

    assert login_response.status_code == 401
    assert login_response.json()["detail"] == "Invalid email or password."


def test_wrong_tenant_login_is_rejected(client):
    password = "StrongPassword-2026!"

    registration = client.post(
        "/api/v1/auth/register",
        json={
            "email": "tenant-bound@example.com",
            "password": password,
            "full_name": "Tenant Bound User",
            "tenant_name": "Correct Tenant",
        },
    )

    assert registration.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "tenant-bound@example.com",
            "password": password,
            "tenant_name": "Wrong Tenant",
        },
    )

    assert login_response.status_code == 401
    assert login_response.json()["detail"] == "Invalid email or password."


def test_login_tenant_name_is_case_and_whitespace_normalized(client):
    password = "StrongPassword-2026!"

    registration = client.post(
        "/api/v1/auth/register",
        json={
            "email": "normalized@example.com",
            "password": password,
            "full_name": "Normalized User",
            "tenant_name": "Normalized Tenant",
        },
    )

    assert registration.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "normalized@example.com",
            "password": password,
            "tenant_name": "  NORMALIZED TENANT  ",
        },
    )

    assert login_response.status_code == 200
    assert login_response.json()["access_token"]


def test_suspended_tenant_cannot_login(client):
    password = "StrongPassword-2026!"

    registration = client.post(
        "/api/v1/auth/register",
        json={
            "email": "suspended-login@example.com",
            "password": password,
            "full_name": "Suspended Login User",
            "tenant_name": "Suspended Login Tenant",
        },
    )

    assert registration.status_code == 201

    from backend.app.core.database import get_db

    db = next(app.dependency_overrides[get_db]())
    try:
        tenant = (
            db.query(Tenant)
            .filter(Tenant.slug == "suspended-login-tenant")
            .first()
        )
        assert tenant is not None

        tenant.status = "suspended"
        db.commit()
    finally:
        db.close()

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "suspended-login@example.com",
            "password": password,
            "tenant_name": "Suspended Login Tenant",
        },
    )

    assert login_response.status_code == 401


def test_existing_token_is_revoked_when_tenant_is_suspended(client):
    password = "StrongPassword-2026!"

    registration = client.post(
        "/api/v1/auth/register",
        json={
            "email": "suspended-token@example.com",
            "password": password,
            "full_name": "Suspended Token User",
            "tenant_name": "Suspended Token Tenant",
        },
    )

    assert registration.status_code == 201

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "suspended-token@example.com",
            "password": password,
            "tenant_name": "Suspended Token Tenant",
        },
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    db = next(app.dependency_overrides[get_db]())
    try:
        tenant = (
            db.query(Tenant)
            .filter(Tenant.slug == "suspended-token-tenant")
            .first()
        )
        assert tenant is not None

        tenant.status = "suspended"
        db.commit()
    finally:
        db.close()

    me_response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert me_response.status_code == 401
    assert me_response.json()["detail"] == (
        "User not found, inactive, or tenant inactive."
    )
