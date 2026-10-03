from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.main import app


def test_security_headers_are_present_on_api_responses():
    response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == (
        "camera=(), microphone=(), geolocation=()"
    )


def test_hsts_can_be_enabled_with_explicit_production_configuration():
    with patch.object(
        settings,
        "security_headers_hsts_enabled",
        True,
    ), patch.object(
        settings,
        "security_headers_hsts_max_age_seconds",
        12345,
    ):
        response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert response.headers["strict-transport-security"] == "max-age=12345"


def test_hsts_is_not_sent_when_disabled():
    with patch.object(
        settings,
        "security_headers_hsts_enabled",
        False,
    ):
        response = TestClient(app).get("/health")

    assert response.status_code == 200
    assert "strict-transport-security" not in response.headers


def test_auth_responses_are_marked_non_cacheable():
    with patch(
        "backend.app.api.routes.auth.authenticate_user",
        return_value=None,
    ):
        response = TestClient(app).post(
            "/api/v1/auth/login",
            json={
                "email": "cache-test@example.com",
                "password": "StrongPassword-2026!",
            },
        )

    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
