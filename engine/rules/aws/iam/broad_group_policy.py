from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class BroadGroupPolicyResult:
    username: str
    group_name: str
    policy_name: str
    policy_arn: str
    policy_version_id: str
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


def check_broad_group_policy(
    username: str,
    group_name: str,
    policy_name: str,
    policy_arn: str,
    policy_version_id: str,
    effect: str | None,
    action: Any,
    resource: Any,
    condition: Any,
) -> BroadGroupPolicyResult | None:
    """
    Detect a broad Allow statement from a managed policy that is
    directly attached to an IAM group containing the user.

    This rule intentionally detects a broad-permission signal. It
    does not claim that the user has unrestricted effective access,
    because AWS permission evaluation can also involve explicit
    denies, permissions boundaries, SCPs, resource policies, and
    session policies.
    """
    if effect != "Allow":
        return None

    if not _contains_wildcard(action):
        return None

    if not _contains_wildcard(resource):
        return None

    return BroadGroupPolicyResult(
        username=username,
        group_name=group_name,
        policy_name=policy_name,
        policy_arn=policy_arn,
        policy_version_id=policy_version_id,
        effect=effect,
        action=action,
        resource=resource,
        condition=condition,
    )


def build_broad_group_policy_finding(
    result: BroadGroupPolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-013",
        title="IAM User Receives Broad Permissions Through Group",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"The IAM user '{result.username}' belongs to the IAM "
            f"group '{result.group_name}', which has a directly "
            f"attached managed policy containing an Allow statement "
            f"with wildcard Action and Resource permissions."
        ),
        evidence={
            "username": result.username,
            "group_name": result.group_name,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "policy_version_id": result.policy_version_id,
            "effect": result.effect,
            "action": result.action,
            "resource": result.resource,
            "condition_present": bool(result.condition),
            "broad_permission": True,
            "permission_source": "iam_group",
        },
        remediation=(
            "Review the managed policy attached to the IAM group "
            "and replace broad wildcard permissions with the minimum "
            "actions and resources required by the group's users. "
            "Also review group membership and whether the policy "
            "should remain directly attached to the group."
        ),
        compliance=["CIS AWS Foundations"],
    )
