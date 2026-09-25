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
