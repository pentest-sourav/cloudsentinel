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


def normalize_required_tag_keys(
    required_tag_keys: list[str] | tuple[str, ...] | None,
) -> tuple[str, ...]:
    """
    Normalize the AWS Security Hub requiredTagKeys parameter.

    Empty/missing/malformed values mean that no explicit
    required-tag-key parameter is configured.
    """
    if not isinstance(
        required_tag_keys,
        (list, tuple),
    ):
        return ()

    normalized: list[str] = []

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue

        key = key.strip()

        if not key:
            continue

        if key.startswith("aws:"):
            continue

        if key not in normalized:
            normalized.append(key)

    return tuple(normalized)


def has_required_tag_keys(
    tags: dict | None,
    required_tag_keys: list[str] | tuple[str, ...] | None,
) -> bool:
    """
    Evaluate AWS Security Hub-style requiredTagKeys semantics.

    When requiredTagKeys is not configured, preserve the existing
    CloudSentinel behaviour: at least one meaningful non-system tag
    must exist.

    When configured, every required key must be present.
    """
    normalized_required_keys = normalize_required_tag_keys(
        required_tag_keys,
    )

    if not normalized_required_keys:
        return has_non_system_tags(tags)

    if not isinstance(tags, dict):
        return False

    actual_keys = {
        key
        for key in tags
        if isinstance(key, str)
        and key
        and not key.startswith("aws:")
    }

    return all(
        required_key in actual_keys
        for required_key in normalized_required_keys
    )
