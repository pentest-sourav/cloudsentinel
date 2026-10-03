import pytest

from backend.app.core.config import Settings


def _settings(**overrides):
    values = {
        "database_url": "sqlite:///cloudsentinel-test.db",
        "redis_url": "redis://localhost:6379/0",
        "jwt_secret_key": "x" * 32,
    }
    values.update(overrides)
    return Settings(**values)


def test_aws_sdk_timeouts_have_safe_defaults():
    configured = _settings()

    assert configured.aws_sdk_connect_timeout_seconds == 10
    assert configured.aws_sdk_read_timeout_seconds == 60


def test_aws_sdk_connect_timeout_is_bounded():
    with pytest.raises(
        ValueError,
        match="AWS_SDK_CONNECT_TIMEOUT_SECONDS",
    ):
        _settings(aws_sdk_connect_timeout_seconds=0)

    with pytest.raises(
        ValueError,
        match="AWS_SDK_CONNECT_TIMEOUT_SECONDS",
    ):
        _settings(aws_sdk_connect_timeout_seconds=61)


def test_aws_sdk_read_timeout_is_bounded():
    with pytest.raises(
        ValueError,
        match="AWS_SDK_READ_TIMEOUT_SECONDS",
    ):
        _settings(aws_sdk_read_timeout_seconds=0)

    with pytest.raises(
        ValueError,
        match="AWS_SDK_READ_TIMEOUT_SECONDS",
    ):
        _settings(aws_sdk_read_timeout_seconds=301)
