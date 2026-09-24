import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from engine.findings.model import Finding, Severity


SENSITIVE_KMS_ACTIONS = frozenset(
    {
        "kms:CreateGrant",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
        "kms:DisableKey",
        "kms:EnableKey",
        "kms:RevokeGrant",
        "kms:TagResource",
        "kms:UntagResource",
    }
)


@dataclass(frozen=True)
class KMSOverlyPermissivePolicyResult:
    key_id: str
    statement_index: int
    principal: Any
    actions: tuple[str, ...]


def _parse_policy(policy: Any) -> dict[str, Any] | None:
    if isinstance(policy, dict):
        return policy

    if not isinstance(policy, str):
        return None

    try:
        parsed = json.loads(unquote(policy))

        if isinstance(parsed, dict):
            return parsed

    except (TypeError, ValueError, json.JSONDecodeError):
        return None

    return None


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value

    return [value]


def _is_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True

    if not isinstance(principal, dict):
        return False

    aws_principal = principal.get("AWS")

    if aws_principal == "*":
        return True

    return isinstance(aws_principal, list) and "*" in aws_principal


def _is_root_principal(principal: Any) -> bool:
    principals = []

    if isinstance(principal, str):
        principals = [principal]
    elif isinstance(principal, dict):
        principals = _as_list(principal.get("AWS"))

    return any(
        isinstance(value, str) and value.endswith(":root")
        for value in principals
    )


def _get_actions(statement: dict[str, Any]) -> tuple[str, ...]:
    actions: list[str] = []

    for action in _as_list(statement.get("Action")):
        if not isinstance(action, str):
            continue

        normalized = action.lower()

        if normalized == "kms:*":
            actions.append(action)
            continue

        if action in SENSITIVE_KMS_ACTIONS:
            actions.append(action)

    return tuple(sorted(set(actions)))


def check_kms_overly_permissive_policy(
    key_id: str,
    key_policy: dict[str, Any] | None,
) -> KMSOverlyPermissivePolicyResult | None:
    if not key_id or not key_policy:
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

        principal = statement.get("Principal")

        if _is_public_principal(principal):
            continue

        if _is_root_principal(principal):
            continue

        actions = _get_actions(statement)

        if not actions:
            continue

        return KMSOverlyPermissivePolicyResult(
            key_id=key_id,
            statement_index=index,
            principal=principal,
            actions=actions,
        )

    return None


def build_kms_overly_permissive_policy_finding(
    result: KMSOverlyPermissivePolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KMS-004",
        title="KMS Key Policy Grants Broad Administrative Access",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="kms_key",
        resource_id=result.key_id,
        description=(
            f"The KMS key policy for {result.key_id} grants a "
            "non-public principal broad or sensitive KMS administrative "
            "permissions. These permissions should be limited to "
            "principals that require them."
        ),
        evidence={
            "key_id": result.key_id,
            "statement_index": result.statement_index,
            "principal": result.principal,
            "actions": list(result.actions),
        },
        remediation=(
            "Review the affected key-policy statement and remove "
            "unnecessary KMS administrative permissions. Grant only "
            "the specific KMS actions required by the principal."
        ),
    )
