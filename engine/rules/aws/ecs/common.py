from typing import Any

from engine.findings.model import Finding, Severity


def non_system_tags(
    tags: Any,
) -> list[dict[str, Any]]:
    if not isinstance(tags, list):
        return []

    return [
        tag
        for tag in tags
        if isinstance(tag, dict)
        and isinstance(tag.get("key", tag.get("Key")), str)
        and bool(tag.get("key", tag.get("Key")))
        and not str(
            tag.get("key", tag.get("Key"))
        ).lower().startswith("aws:")
    ]


def normalize_required_tag_keys(
    required_tag_keys: list[str] | tuple[str, ...] | None,
) -> tuple[str, ...]:
    if not isinstance(required_tag_keys, (list, tuple)):
        return ()

    normalized: list[str] = []

    for key in required_tag_keys:
        if not isinstance(key, str):
            continue

        key = key.strip()

        if not key:
            continue

        if key.lower().startswith("aws:"):
            continue

        if key not in normalized:
            normalized.append(key)

    return tuple(normalized)


def has_required_tag_keys(
    tags: Any,
    required_tag_keys: list[str] | tuple[str, ...] | None,
) -> bool:
    normalized_required_keys = normalize_required_tag_keys(
        required_tag_keys,
    )

    valid_tags = non_system_tags(tags)

    if not normalized_required_keys:
        return bool(valid_tags)

    actual_keys = {
        tag.get("key", tag.get("Key"))
        for tag in valid_tags
        if isinstance(
            tag.get("key", tag.get("Key")),
            str,
        )
    }

    return all(
        required_key in actual_keys
        for required_key in normalized_required_keys
    )


def finding(
    *,
    rule_id: str,
    title: str,
    severity: Severity,
    resource_type: str,
    resource_id: str,
    description: str,
    evidence: dict[str, Any],
    remediation: str,
    compliance: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        provider="aws",
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        evidence=evidence,
        remediation=remediation,
        compliance=[compliance],
    )


def containers(resource: dict[str, Any]) -> list[dict[str, Any]]:
    values = resource.get("container_definitions", [])

    return [
        value
        for value in values
        if isinstance(value, dict)
    ]


def is_windows(resource: dict[str, Any]) -> bool:
    family = resource.get("operating_system_family")

    return (
        isinstance(family, str)
        and family.upper().startswith("WINDOWS")
    )


def is_linux_or_unspecified(
    resource: dict[str, Any],
) -> bool:
    family = resource.get("operating_system_family")

    if not family:
        return True

    return (
        isinstance(family, str)
        and family.upper().startswith("LINUX")
    )
