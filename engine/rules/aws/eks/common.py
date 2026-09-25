def parse_kubernetes_version(
    version: str | None,
) -> tuple[int, int] | None:
    if not isinstance(version, str):
        return None

    parts = version.strip().split(".")

    if len(parts) < 2:
        return None

    try:
        major = int(parts[0])
        minor = int(parts[1])
    except (TypeError, ValueError):
        return None

    return major, minor


def is_supported_kubernetes_version(
    version: str | None,
    minimum_version: tuple[int, int] = (1, 34),
) -> bool:
    parsed = parse_kubernetes_version(version)

    if parsed is None:
        return False

    return parsed >= minimum_version


def has_non_system_tags(
    tags: dict | None,
) -> bool:
    if not isinstance(tags, dict):
        return False

    return any(
        isinstance(key, str)
        and key
        and not key.startswith("aws:")
        for key in tags
    )
