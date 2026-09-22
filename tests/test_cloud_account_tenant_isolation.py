import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app


PASSWORD = "StrongPassword-2026!"


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


def register_user(client, email, tenant_name):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": PASSWORD,
            "full_name": tenant_name + " Owner",
            "tenant_name": tenant_name,
        },
    )

    assert response.status_code == 201
    return response.json()


def login_user(client, email):
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": email,
            "password": PASSWORD,
        },
    )

    assert response.status_code == 200
    return response.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def create_account(client, token, name, provider="aws"):
    response = client.post(
        "/api/v1/cloud-accounts",
        headers=auth_headers(token),
        json={
            "name": name,
            "provider": provider,
            "external_account_id": "123456789012",
        },
    )

    assert response.status_code == 201
    return response.json()


def test_cloud_accounts_are_isolated_between_tenants(client):
    register_user(
        client,
        "tenant-a@example.com",
        "Tenant A",
    )

    register_user(
        client,
        "tenant-b@example.com",
        "Tenant B",
    )

    token_a = login_user(
        client,
        "tenant-a@example.com",
    )

    token_b = login_user(
        client,
        "tenant-b@example.com",
    )

    account_a = create_account(
        client,
        token_a,
        "Tenant A AWS Account",
    )

    account_b = create_account(
        client,
        token_b,
        "Tenant B AWS Account",
    )

    list_a = client.get(
        "/api/v1/cloud-accounts",
        headers=auth_headers(token_a),
    )

    assert list_a.status_code == 200
    assert len(list_a.json()) == 1
    assert list_a.json()[0]["id"] == account_a["id"]
    assert list_a.json()[0]["name"] == "Tenant A AWS Account"

    list_b = client.get(
        "/api/v1/cloud-accounts",
        headers=auth_headers(token_b),
    )

    assert list_b.status_code == 200
    assert len(list_b.json()) == 1
    assert list_b.json()[0]["id"] == account_b["id"]
    assert list_b.json()[0]["name"] == "Tenant B AWS Account"

    account_a_from_b = client.get(
        f"/api/v1/cloud-accounts/{account_a['id']}",
        headers=auth_headers(token_b),
    )

    assert account_a_from_b.status_code == 404
    assert account_a_from_b.json()["detail"] == "Cloud account not found"

    account_b_from_a = client.get(
        f"/api/v1/cloud-accounts/{account_b['id']}",
        headers=auth_headers(token_a),
    )

    assert account_b_from_a.status_code == 404
    assert account_b_from_a.json()["detail"] == "Cloud account not found"


def test_cloud_account_requires_authentication(client):
    response = client.get("/api/v1/cloud-accounts")

    assert response.status_code == 401


def test_cloud_account_creation_uses_authenticated_tenant(client):
    register_user(
        client,
        "tenant-owner@example.com",
        "Authenticated Tenant",
    )

    token = login_user(
        client,
        "tenant-owner@example.com",
    )

    response = client.post(
        "/api/v1/cloud-accounts",
        headers=auth_headers(token),
        json={
            "name": "Authenticated AWS Account",
            "provider": "aws",
            "external_account_id": "999999999999",
        },
    )

    assert response.status_code == 201

    account = response.json()

    assert account["name"] == "Authenticated AWS Account"
    assert "tenant_id" not in account


def test_cloud_account_detail_is_available_to_owner_tenant(client):
    register_user(
        client,
        "detail-owner@example.com",
        "Detail Owner Tenant",
    )

    token = login_user(
        client,
        "detail-owner@example.com",
    )

    account = create_account(
        client,
        token,
        "Detail Test Account",
    )

    response = client.get(
        f"/api/v1/cloud-accounts/{account['id']}",
        headers=auth_headers(token),
    )

    assert response.status_code == 200
    assert response.json()["id"] == account["id"]
    assert response.json()["name"] == "Detail Test Account"


def test_cloud_account_accepts_aws_connection_configuration(client):
    register_user(
        client,
        "aws-config@example.com",
        "AWS Config Tenant",
    )

    token = login_user(
        client,
        "aws-config@example.com",
    )

    response = client.post(
        "/api/v1/cloud-accounts",
        headers=auth_headers(token),
        json={
            "name": "Production AWS Account",
            "provider": "aws",
            "external_account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/CloudSentinelAuditRole",
            "external_id": "cloudsentinel-external-2026",
            "region": "ap-south-1",
        },
    )

    assert response.status_code == 201

    account = response.json()

    assert account["name"] == "Production AWS Account"
    assert account["provider"] == "aws"
    assert account["external_account_id"] == "123456789012"
    assert account["role_arn"] == (
        "arn:aws:iam::123456789012:role/CloudSentinelAuditRole"
    )
    assert account["region"] == "ap-south-1"
    assert "external_id" not in account


def test_cloud_account_connection_configuration_is_available_in_detail(client):
    register_user(
        client,
        "aws-detail@example.com",
        "AWS Detail Tenant",
    )

    token = login_user(
        client,
        "aws-detail@example.com",
    )

    create_response = client.post(
        "/api/v1/cloud-accounts",
        headers=auth_headers(token),
        json={
            "name": "Detailed AWS Account",
            "provider": "aws",
            "external_account_id": "210987654321",
            "role_arn": "arn:aws:iam::210987654321:role/AuditRole",
            "external_id": "private-external-id",
            "region": "ap-south-1",
        },
    )

    assert create_response.status_code == 201
    account_id = create_response.json()["id"]

    detail_response = client.get(
        f"/api/v1/cloud-accounts/{account_id}",
        headers=auth_headers(token),
    )

    assert detail_response.status_code == 200

    account = detail_response.json()

    assert account["role_arn"] == (
        "arn:aws:iam::210987654321:role/AuditRole"
    )
    assert account["region"] == "ap-south-1"
    assert "external_id" not in account
