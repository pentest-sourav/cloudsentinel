from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.core.metrics import metrics_registry


def test_request_body_limit_rejects_oversized_payload():
    with patch(
        "backend.app.main.settings.max_request_body_bytes",
        10,
    ):
        response = TestClient(app).post(
            "/api/v1/auth/login",
            content=b"x" * 11,
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json()["detail"] == "Request body is too large."
    assert response.headers.get("x-request-id")


def test_invalid_content_length_is_rejected():
    with patch(
        "backend.app.main.settings.max_request_body_bytes",
        100,
    ):
        response = TestClient(app).post(
            "/api/v1/auth/login",
            content=b"{}",
            headers={
                "content-type": "application/json",
                "content-length": "invalid",
            },
        )

    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid Content-Length header."
    assert response.headers.get("x-request-id")


def test_metrics_endpoint_is_disabled_by_default():
    with patch(
        "backend.app.main.settings.metrics_enabled",
        False,
    ):
        response = TestClient(app).get("/metrics")

    assert response.status_code == 404


def test_metrics_endpoint_exposes_request_metrics():
    client = TestClient(app)

    with patch(
        "backend.app.main.settings.metrics_enabled",
        True,
    ):
        response = client.get("/health")
        assert response.status_code == 200

        metrics_response = client.get("/metrics")

    assert metrics_response.status_code == 200
    assert "cloudsentinel_http_requests_total" in metrics_response.text
    assert 'method="GET"' in metrics_response.text
    assert "cloudsentinel_process_uptime_seconds" in metrics_response.text


def test_metrics_endpoint_requires_configured_token():
    client = TestClient(app)

    with patch(
        "backend.app.main.settings.metrics_enabled",
        True,
    ), patch(
        "backend.app.main.settings.metrics_auth_token",
        "m" * 32,
    ):
        unauthorized = client.get("/metrics")
        authorized = client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {'m' * 32}"},
        )

    assert unauthorized.status_code == 401
    assert authorized.status_code == 200
