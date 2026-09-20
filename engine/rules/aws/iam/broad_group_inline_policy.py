from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class BroadGroupInlinePolicyResult:
    group_name: str
    policy_name: str
    statement_index: int
    effect: str
    action: Any
    resource: Any
    condition: Any


def _contains_wildcard(value: Any) -> bool:
    """
    Return True when an IAM Action or Resource value contains
    the full wildcard value '*'.

    IAM policy values may be represented either as a single
    string or as a list of strings.
    """
    if value == "*":
        return True

    if isinstance(value, list):
        return "*" in value

    return False


def check_broad_group_inline_policy(
    group_name: str,
    policy_name: str,
    statement_index: int,
    effect: str | None,
    action: Any,
    resource: Any,
    condition: Any,
) -> BroadGroupInlinePolicyResult | None:
    """
    Detect a broad Allow statement from an inline policy directly
    attached to an IAM group.

    This rule intentionally detects a broad-permission signal. It
    does not claim that every user who may belong to the group has
    unrestricted effective access, because AWS permission evaluation
    can also involve explicit denies, permissions boundaries, SCPs,
    resource policies, and session policies.
    """
    if effect != "Allow":
        return None

    if not _contains_wildcard(action):
        return None

    if not _contains_wildcard(resource):
        return None

    return BroadGroupInlinePolicyResult(
        group_name=group_name,
        policy_name=policy_name,
        statement_index=statement_index,
        effect=effect,
        action=action,
        resource=resource,
        condition=condition,
    )


def build_broad_group_inline_policy_finding(
    result: BroadGroupInlinePolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-015",
        title="IAM Group Inline Policy Grants Broad Permissions",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_group",
        resource_id=result.group_name,
        description=(
            f"The IAM group '{result.group_name}' has an inline "
            f"policy named '{result.policy_name}' containing an "
            f"Allow statement with wildcard Action and Resource "
            f"permissions."
        ),
        evidence={
            "group_name": result.group_name,
            "policy_name": result.policy_name,
            "statement_index": result.statement_index,
            "effect": result.effect,
            "action": result.action,
            "resource": result.resource,
            "condition_present": bool(result.condition),
            "broad_permission": True,
            "permission_source": "iam_group_inline",
        },
        remediation=(
            "Review the inline policy directly attached to the IAM "
            "group and replace broad wildcard permissions with the "
            "minimum actions and resources required. Also review "
            "group membership, permissions boundaries, SCPs, resource "
            "policies, and explicit Deny statements when evaluating "
            "effective access."
        ),
        compliance=["CIS AWS Foundations"],
    )
