from fnmatch import fnmatchcase
from typing import Any


def _values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]

    if isinstance(value, (list, tuple, set)):
        return [
            item
            for item in value
            if isinstance(item, str)
        ]

    return []


def first_matching_action(
    action: Any,
    target_actions: set[str],
) -> str | None:
    """
    Return the first sensitive action covered by the policy Action
    value.

    IAM action names are treated case-insensitively. Policy-side
    wildcards such as iam:* are supported.
    """
    policy_actions = [
        item.strip().lower()
        for item in _values(action)
        if item.strip()
    ]

    for target in sorted(target_actions):
        target_normalized = target.lower()

        for policy_action in policy_actions:
            if fnmatchcase(
                target_normalized,
                policy_action,
            ):
                return target

    return None


def has_wildcard_resource(resource: Any) -> bool:
    """
    Return True when the statement grants access to the literal
    wildcard resource '*'.

    A wildcard embedded inside an ARN is intentionally not treated
    as account-wide Resource='*'.
    """
    return any(
        item.strip() == "*"
        for item in _values(resource)
    )
