import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class KMSPublicAccessResult:
    key_id: str
    statement_index: int
    actions: tuple[str, ...]


def _parse_policy(policy: Any) -> dict[str, Any] | None:
    if isinstance(policy, dict):
        return policy

    if not isinstance(policy, str):
        return None

    try:
        decoded = unquote(policy)
        parsed = json.loads(decoded)

        if isinstance(parsed, dict):
            return parsed

    except (TypeError, ValueError, json.JSONDecodeError):
        return None

    return None


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value

    return [value]


def _has_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True

    if not isinstance(principal, dict):
        return False

    aws_principal = principal.get("AWS")

    if aws_principal == "*":
        return True

    if isinstance(aws_principal, list) and "*" in aws_principal:
        return True

    return False


def _has_restrictive_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("Condition")

    return isinstance(condition, dict) and bool(condition)


def _is_kms_action(action: Any) -> bool:
    if not isinstance(action, str):
        return False

    normalized = action.lower()

    return normalized == "kms:*" or normalized.startswith("kms:")


def _get_kms_actions(statement: dict[str, Any]) -> tuple[str, ...]:
    actions = [
        str(action)
        for action in _as_list(statement.get("Action"))
        if _is_kms_action(action)
    ]

    return tuple(sorted(set(actions)))


def check_kms_public_access(
    key_id: str,
    key_policy: dict[str, Any] | None,
) -> KMSPublicAccessResult | None:
    if not key_id:
        return None

    if not key_policy:
        return None

    policy = _parse_policy(key_policy.get("policy"))

    if not policy:
        return None

    statements = policy.get("Statement")

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return None

    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            continue

        if str(statement.get("Effect", "")).lower() != "allow":
            continue

        if not _has_public_principal(statement.get("Principal")):
            continue

        if _has_restrictive_condition(statement):
            continue

        actions = _get_kms_actions(statement)

        if not actions:
            continue

        return KMSPublicAccessResult(
            key_id=key_id,
            statement_index=index,
            actions=actions,
        )

    return None


def build_kms_public_access_finding(
    result: KMSPublicAccessResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KMS-003",
        title="KMS Key Policy Allows Public Access",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="kms_key",
        resource_id=result.key_id,
        description=(
            f"The KMS key policy for {result.key_id} contains an "
            "Allow statement with a public principal and KMS actions "
            "without a policy condition restricting that access."
        ),
        evidence={
            "key_id": result.key_id,
            "statement_index": result.statement_index,
            "actions": list(result.actions),
            "public_principal": True,
        },
        remediation=(
            "Remove the public principal from the KMS key policy and "
            "grant access only to the required AWS principals. Use "
            "appropriate policy conditions when service or "
            "cross-account access is intentionally required."
        ),
    )
