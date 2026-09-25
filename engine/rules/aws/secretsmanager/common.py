from datetime import datetime, timezone
from typing import Any


DEFAULT_UNUSED_DAYS = 90
DEFAULT_MAX_ROTATION_DAYS = 90


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


def ensure_utc(
    value: datetime,
) -> datetime:
    if value.tzinfo is None:
        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(timezone.utc)


def is_older_than_days(
    value: datetime | None,
    days: int,
    *,
    now: datetime | None = None,
) -> bool:
    if value is None:
        return True

    current = (
        ensure_utc(now)
        if now is not None
        else datetime.now(timezone.utc)
    )

    observed = ensure_utc(value)

    return (
        current - observed
    ).total_seconds() > days * 86400


def format_datetime(
    value: datetime | None,
) -> str | None:
    if value is None:
        return None

    return ensure_utc(value).isoformat()
