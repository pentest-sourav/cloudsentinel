from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from backend.app.core.config import settings
from backend.app.core.rate_limit import RateLimitDecision, RateLimiter
from backend.app.main import app


def test_rate_limiter_allows_within_limit():
    request = Mock()
    request.client.host = "127.0.0.1"

    limiter = RateLimiter()

    decisions = [
        limiter._check_fallback(
            key="test",
            limit=2,
            window_seconds=60,
        )
        for _ in range(3)
    ]

    assert decisions[0].allowed is True
    assert decisions[0].remaining == 1
    assert decisions[1].allowed is True
    assert decisions[1].remaining == 0
    assert decisions[2].allowed is False
    assert decisions[2].retry_after >= 1


def test_rate_limiter_uses_redis_window():
    request = Mock()
    request.client.host = "127.0.0.1"

    client = Mock()
    client.time.return_value = (120, 0)
    client.incr.return_value = 1

    queue = Mock()
    queue.client = client

    limiter = RateLimiter(
        queue_factory=lambda: queue,
    )

    decision = limiter.check(
        request,
        scope="auth",
        limit=5,
        window_seconds=60,
    )

    assert decision.allowed is True
    client.incr.assert_called_once_with(
        "cloudsentinel:rate_limit:auth:127.0.0.1:2"
    )
    client.expire.assert_called_once_with(
        "cloudsentinel:rate_limit:auth:127.0.0.1:2",
        60,
    )


def test_rate_limiter_falls_back_when_redis_fails():
    request = Mock()
    request.client.host = "127.0.0.1"

    queue = Mock()
    queue.client.time.return_value = (120, 0)
    queue.client.incr.side_effect = ConnectionError(
        "redis unavailable"
    )

    limiter = RateLimiter(
        queue_factory=lambda: queue,
    )

    decision = limiter.check(
        request,
        scope="auth",
        limit=1,
        window_seconds=60,
    )

    assert decision.allowed is True


def test_authentication_rate_limit_returns_429():
    limiter = Mock()
    limiter.check.return_value = RateLimitDecision(
        allowed=False,
        remaining=0,
        retry_after=42,
    )

    with patch(
        "backend.app.main.rate_limiter",
        limiter,
    ):
        response = TestClient(app).post(
            "/api/v1/auth/login",
            json={
                "email": "rate@example.com",
                "password": "StrongPassword-2026!",
            },
        )

    assert response.status_code == 429
    assert response.json()["detail"] == (
        "Rate limit exceeded. Please retry later."
    )
    assert response.headers["retry-after"] == "42"
    assert response.headers["x-ratelimit-remaining"] == "0"

    limiter.check.assert_called_once()
    call_kwargs = limiter.check.call_args.kwargs
    assert call_kwargs["scope"] == "auth-login"
    assert call_kwargs["limit"] == settings.rate_limit_auth_max_requests


def test_mutation_exposes_rate_limit_headers_without_database_dependency():
    limiter = Mock()
    limiter.check.return_value = RateLimitDecision(
        allowed=True,
        remaining=7,
        retry_after=0,
    )

    with patch(
        "backend.app.main.rate_limiter",
        limiter,
    ):
        with patch(
            "backend.app.api.routes.auth.authenticate_user",
            return_value=None,
        ):
            response = TestClient(app).post(
                "/api/v1/auth/login",
                json={
                    "email": "rate-success@example.com",
                    "password": "StrongPassword-2026!",
                },
            )

    assert response.status_code == 401
    assert response.headers["x-ratelimit-remaining"] == "7"
    assert response.headers["x-ratelimit-limit"] == str(
        settings.rate_limit_auth_max_requests
    )


def test_rate_limiter_uses_forwarded_client_only_for_trusted_proxy():
    request = Mock()
    request.client.host = "10.0.0.10"
    request.headers.get.return_value = (
        "203.0.113.50, 10.0.0.10"
    )

    with patch.object(
        settings,
        "trusted_proxy_ips",
        "10.0.0.0/24",
    ):
        assert RateLimiter._client_ip(request) == "203.0.113.50"


def test_rate_limiter_does_not_trust_forwarded_header_from_public_peer():
    request = Mock()
    request.client.host = "198.51.100.10"
    request.headers.get.return_value = "203.0.113.50"

    with patch.object(
        settings,
        "trusted_proxy_ips",
        "10.0.0.0/24",
    ):
        assert RateLimiter._client_ip(request) == "198.51.100.10"
