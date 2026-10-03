import pytest
from pydantic import ValidationError

from backend.app.core.config import Settings


def _settings(**overrides):
    values = {
        "database_url": "sqlite:///cloudsentinel.db",
        "redis_url": "redis://localhost:6379/0",
        "jwt_secret_key": "x" * 32,
        "security_headers_hsts_enabled": True,
        "log_format": "json",
    }
    values.update(overrides)
    return Settings(**values)


def test_production_rejects_short_jwt_secret():
    with pytest.raises(ValidationError, match="at least 32"):
        _settings(
            app_environment="production",
            jwt_secret_key="too-short",
        )


def test_production_accepts_strong_jwt_secret():
    config = _settings(
        app_environment="production",
        jwt_secret_key="x" * 64,
    )

    assert config.app_environment == "production"


def test_wildcard_cors_is_rejected():
    with pytest.raises(ValidationError, match="Wildcard CORS"):
        _settings(cors_allowed_origins="*")


def test_request_body_limit_must_be_positive():
    with pytest.raises(ValidationError, match="MAX_REQUEST_BODY_BYTES"):
        _settings(max_request_body_bytes=0)


def test_production_rejects_weak_metrics_token():
    with pytest.raises(ValidationError, match="METRICS_AUTH_TOKEN"):
        _settings(
            app_environment="production",
            metrics_enabled=True,
            metrics_auth_token="short",
        )


def test_production_accepts_metrics_token():
    config = _settings(
        app_environment="production",
        metrics_enabled=True,
        metrics_auth_token="m" * 32,
    )

    assert config.metrics_enabled is True


def test_rate_limit_settings_must_be_positive():
    with pytest.raises(ValidationError, match="Rate limit settings"):
        _settings(rate_limit_global_max_requests=0)


def test_invalid_log_format_is_rejected():
    with pytest.raises(ValidationError, match="LOG_FORMAT"):
        _settings(log_format="xml")


def test_invalid_log_level_is_rejected():
    with pytest.raises(ValidationError, match="LOG_LEVEL"):
        _settings(log_level="LOUD")


def test_scan_queue_settings_must_be_positive():
    with pytest.raises(ValidationError, match="Scan queue settings"):
        _settings(scan_queue_recovery_batch_size=0)
