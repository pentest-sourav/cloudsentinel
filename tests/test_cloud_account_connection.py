from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.core.database import Base, get_db
from backend.app.main import app


PASSWORD = "StrongPassword-2026!"


def _client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
    )

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    return TestClient(app), engine


def _register_and_login(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "connection@example.com",
            "password": PASSWORD,
            "full_name": "Connection Owner",
            "tenant_name": "Connection Tenant",
        },
    )
    assert response.status_code == 201

    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "connection@example.com",
            "password": PASSWORD,
        },
    )
    assert response.status_code == 200

    return response.json()["access_token"]


def _headers(token):
    return {"Authorization": f"Bearer {token}"}


def _create_account(client, token):
    response = client.post(
        "/api/v1/cloud-accounts",
        headers=_headers(token),
        json={
            "name": "Production AWS",
            "provider": "aws",
            "external_account_id": "123456789012",
            "role_arn": (
                "arn:aws:iam::123456789012:"
                "role/CloudSentinelReadOnly"
            ),
            "region": "eu-north-1",
        },
    )

    assert response.status_code == 201
    return response.json()


def test_external_id_is_server_generated():
    client, engine = _client()

    try:
        token = _register_and_login(client)

        account = _create_account(client, token)

        assert account["id"] > 0
        assert "external_id" not in account

        setup = client.get(
            f"/api/v1/cloud-accounts/{account['id']}/connection",
            headers=_headers(token),
        )

        assert setup.status_code == 200

        payload = setup.json()

        assert payload["external_account_id"] == "123456789012"
        assert payload["role_arn"].endswith(
            ":role/CloudSentinelReadOnly"
        )
        assert payload["external_id"].startswith("cs-")
        assert len(payload["external_id"]) > 30

    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_connection_configuration_is_tenant_isolated():
    client, engine = _client()

    try:
        token = _register_and_login(client)
        account = _create_account(client, token)

        other = client.post(
            "/api/v1/auth/register",
            json={
                "email": "other@example.com",
                "password": PASSWORD,
                "full_name": "Other Owner",
                "tenant_name": "Other Tenant",
            },
        )
        assert other.status_code == 201

        other_login = client.post(
            "/api/v1/auth/login",
            json={
                "email": "other@example.com",
                "password": PASSWORD,
            },
        )
        assert other_login.status_code == 200

        other_token = other_login.json()["access_token"]

        response = client.get(
            f"/api/v1/cloud-accounts/{account['id']}/connection",
            headers=_headers(other_token),
        )

        assert response.status_code == 404

    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_role_arn_account_must_match_account_id():
    client, engine = _client()

    try:
        token = _register_and_login(client)

        response = client.post(
            "/api/v1/cloud-accounts",
            headers=_headers(token),
            json={
                "name": "Mismatched AWS Account",
                "provider": "aws",
                "external_account_id": "123456789012",
                "role_arn": (
                    "arn:aws:iam::999999999999:"
                    "role/CloudSentinelReadOnly"
                ),
            },
        )

        assert response.status_code == 400
        assert "must match" in response.json()["detail"]

    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_connection_test_uses_assume_role_and_verifies_identity():
    client, engine = _client()

    try:
        token = _register_and_login(client)
        account = _create_account(client, token)

        class FakeSTS:
            def get_caller_identity(self):
                return {
                    "Account": "123456789012",
                    "Arn": (
                        "arn:aws:sts::123456789012:"
                        "assumed-role/CloudSentinelReadOnly/"
                        "CloudSentinelConnectionTest"
                    ),
                    "UserId": "AROATEST:CloudSentinelConnectionTest",
                }

        class FakeSession:
            def client(self, service_name):
                assert service_name == "sts"
                return FakeSTS()

        with patch(
            "backend.app.services.cloud_account_connection_service."
            "create_aws_session",
            return_value=FakeSession(),
        ) as assume_role:
            response = client.post(
                f"/api/v1/cloud-accounts/{account['id']}/test",
                headers=_headers(token),
            )

        assert response.status_code == 200

        payload = response.json()

        assert payload["connected"] is True
        assert payload["status"] == "connected"
        assert payload["actual_account_id"] == "123456789012"
        assert "assumed-role/CloudSentinelReadOnly" in (
            payload["assumed_role_arn"]
        )

        assume_role.assert_called_once()

    finally:
        app.dependency_overrides.clear()
        engine.dispose()
