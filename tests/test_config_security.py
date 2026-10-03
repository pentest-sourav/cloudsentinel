import pytest
from pydantic import ValidationError

from backend.app.core.config import Settings


def _settings(**overrides):
    values = {
        "database_url": "sqlite:///cloudsentinel.db",
        "redis_url": "redis://localhost:6379/0",
        "jwt_secret_key": "x" * 32,
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
