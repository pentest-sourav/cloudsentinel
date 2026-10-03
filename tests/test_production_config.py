import pytest

from backend.app.core.config import Settings


def production_settings(**overrides):
    values = {
        "database_url": "postgresql+psycopg://user:pass@localhost/db",
        "redis_url": "redis://localhost:6379/0",
        "jwt_secret_key": "a" * 64,
        "app_environment": "production",
        "security_headers_hsts_enabled": True,
        "log_format": "json",
        "jwt_access_token_expire_minutes": 30,
    }
    values.update(overrides)
    return Settings(**values)


def test_production_configuration_accepts_secure_defaults():
    settings = production_settings()

    assert settings.app_environment == "production"
    assert settings.security_headers_hsts_enabled is True
    assert settings.log_format == "json"


@pytest.mark.parametrize(
    "overrides, expected",
    [
        (
            {"security_headers_hsts_enabled": False},
            "SECURITY_HEADERS_HSTS_ENABLED must be true in production.",
        ),
        (
            {"log_format": "text"},
            "LOG_FORMAT must be json in production.",
        ),
        (
            {"jwt_access_token_expire_minutes": 61},
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES must be <= 60 in production.",
        ),
        (
            {"jwt_secret_key": "short"},
            "JWT_SECRET_KEY must be at least 32 characters in production.",
        ),
    ],
)
def test_production_configuration_rejects_insecure_settings(overrides, expected):
    with pytest.raises(ValueError, match=expected):
        production_settings(**overrides)


def test_non_production_configuration_can_use_development_logging():
    settings = Settings(
        database_url="postgresql+psycopg://user:pass@localhost/db",
        redis_url="redis://localhost:6379/0",
        jwt_secret_key="short",
        app_environment="development",
        log_format="text",
    )

    assert settings.log_format == "text"


def test_jwt_expiration_must_be_positive():
    with pytest.raises(
        ValueError,
        match="JWT_ACCESS_TOKEN_EXPIRE_MINUTES must be > 0",
    ):
        production_settings(jwt_access_token_expire_minutes=0)
