import pytest

from backend.app.core.config import Settings, settings
from backend.app.core.database import _engine_options


def test_sqlite_engine_does_not_apply_network_pool_options():
    assert _engine_options("sqlite://") == {}


def test_postgres_engine_uses_bounded_pool_settings():
    original = (
        settings.database_pool_size,
        settings.database_max_overflow,
        settings.database_pool_timeout_seconds,
        settings.database_pool_recycle_seconds,
    )

    try:
        settings.database_pool_size = 5
        settings.database_max_overflow = 10
        settings.database_pool_timeout_seconds = 30
        settings.database_pool_recycle_seconds = 1800

        assert _engine_options(
            "postgresql+psycopg://user:password@db/cloudsentinel"
        ) == {
            "pool_pre_ping": True,
            "pool_size": 5,
            "max_overflow": 10,
            "pool_timeout": 30,
            "pool_recycle": 1800,
        }
    finally:
        (
            settings.database_pool_size,
            settings.database_max_overflow,
            settings.database_pool_timeout_seconds,
            settings.database_pool_recycle_seconds,
        ) = original


def _settings(**overrides):
    values = {
        "database_url": "postgresql+psycopg://user:password@db/cloudsentinel",
        "redis_url": "redis://:password@redis:6379/0",
        "jwt_secret_key": "test-secret-that-is-long-enough-for-validation",
        "security_headers_hsts_enabled": True,
        "log_format": "json",
        "app_environment": "production",
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("database_pool_size", 0, "DATABASE_POOL_SIZE must be > 0"),
        ("database_max_overflow", -1, "DATABASE_MAX_OVERFLOW must be >= 0"),
        (
            "database_pool_timeout_seconds",
            0,
            "DATABASE_POOL_TIMEOUT_SECONDS and DATABASE_POOL_RECYCLE_SECONDS must be > 0",
        ),
        (
            "database_pool_recycle_seconds",
            0,
            "DATABASE_POOL_TIMEOUT_SECONDS and DATABASE_POOL_RECYCLE_SECONDS must be > 0",
        ),
    ],
)
def test_database_pool_settings_have_runtime_guardrails(field, value, message):
    with pytest.raises(ValueError, match=message):
        _settings(**{field: value})
