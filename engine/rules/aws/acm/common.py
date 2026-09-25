from datetime import datetime, timezone
from typing import Any


DEFAULT_DAYS_TO_EXPIRATION = 30
MIN_RSA_KEY_LENGTH = 2048


def ensure_utc(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(timezone.utc)


def days_until(
    value: datetime,
    *,
    now: datetime | None = None,
) -> float:
    current = (
        ensure_utc(now)
        if now is not None
        else datetime.now(timezone.utc)
    )

    return (
        ensure_utc(value) - current
    ).total_seconds() / 86400


def has_non_system_tags(
    tags: list[dict[str, Any]] | None,
) -> bool:
    if not isinstance(tags, list):
        return False

    for tag in tags:
        if not isinstance(tag, dict):
            continue

        key = tag.get("Key")

        if (
            isinstance(key, str)
            and key
            and not key.startswith("aws:")
        ):
            return True

    return False


def format_datetime(
    value: datetime | None,
) -> str | None:
    if value is None:
        return None

    return ensure_utc(value).isoformat()
