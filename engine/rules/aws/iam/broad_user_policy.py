from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class BroadUserPolicyResult:
    username: str
    policy_name: str
    policy_arn: str
    policy_version_id: str
    effect: str
    action: Any
    resource: Any
    condition: Any


def _contains_wildcard(value: Any) -> bool:
    if value == "*":
        return True

    if isinstance(value, list):
        return "*" in value

    return False


def check_broad_user_policy(
    username: str,
    policy_name: str,
    policy_arn: str,
    policy_version_id: str,
    effect: str | None,
    action: Any,
    resource: Any,
    condition: Any,
) -> BroadUserPolicyResult | None:
    if effect != "Allow":
        return None

    if not _contains_wildcard(action):
        return None

    if not _contains_wildcard(resource):
        return None

    return BroadUserPolicyResult(
        username=username,
        policy_name=policy_name,
        policy_arn=policy_arn,
        policy_version_id=policy_version_id,
        effect=effect,
        action=action,
        resource=resource,
        condition=condition,
    )


def build_broad_user_policy_finding(
    result: BroadUserPolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-012",
        title="IAM User Has Broad Direct Permissions",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"The IAM user '{result.username}' has a directly "
            f"attached managed policy containing an Allow statement "
            f"with wildcard Action and Resource permissions."
        ),
        evidence={
            "username": result.username,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "policy_version_id": result.policy_version_id,
            "effect": result.effect,
            "action": result.action,
            "resource": result.resource,
            "condition_present": bool(result.condition),
            "broad_permission": True,
        },
        remediation=(
            "Review the directly attached policy and replace broad "
            "wildcard permissions with the minimum actions and "
            "resources required by the user's role. Also review "
            "whether the policy should remain directly attached "
            "to the user."
        ),
        compliance=["CIS AWS Foundations"],
    )
