import pytest

from backend.app.core.config import Settings


def _settings(**overrides):
    values = {
        "database_url": "sqlite:///test.db",
        "redis_url": "redis://localhost:6379/0",
        "jwt_secret_key": "x" * 64,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.parametrize(
    "duration_seconds",
    [899, 43_201],
)
def test_aws_sts_session_duration_must_use_aws_supported_bounds(
    duration_seconds,
):
    with pytest.raises(
        ValueError,
        match="AWS_STS_SESSION_DURATION_SECONDS",
    ):
        _settings(
            aws_sts_session_duration_seconds=duration_seconds,
        )


def test_aws_sts_session_duration_defaults_to_15_minutes():
    assert _settings().aws_sts_session_duration_seconds == 900
