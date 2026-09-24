from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity
from engine.rules.aws.iam.policy_scope import first_matching_action
from engine.rules.aws.iam.privilege_management_action import (
    PRIVILEGE_MANAGEMENT_ACTIONS,
)


@dataclass(frozen=True)
class PrivilegedRoleWithoutBoundaryResult:
    role_name: str
    role_arn: str
    permissions_boundary: str | None
    policy_name: str
    policy_arn: str | None
    action: Any
    matching_action: str
    resource: Any
    permission_source: str
    condition: Any
    statement_index: int | None


def check_privileged_role_without_boundary(
    role_name: str,
    role_arn: str,
    permissions_boundary: str | None,
    policy_name: str,
    policy_arn: str | None,
    action: Any,
    resource: Any,
    permission_source: str,
    condition: Any,
    statement_index: int | None,
) -> PrivilegedRoleWithoutBoundaryResult | None:
    if permissions_boundary:
        return None

    matching_action = first_matching_action(
        action,
        PRIVILEGE_MANAGEMENT_ACTIONS,
    )

    if matching_action is None:
        return None

    return PrivilegedRoleWithoutBoundaryResult(
        role_name=role_name,
        role_arn=role_arn,
        permissions_boundary=permissions_boundary,
        policy_name=policy_name,
        policy_arn=policy_arn,
        action=action,
        matching_action=matching_action,
        resource=resource,
        permission_source=permission_source,
        condition=condition,
        statement_index=statement_index,
    )


def build_privileged_role_without_boundary_finding(
    result: PrivilegedRoleWithoutBoundaryResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-038",
        title="Privileged IAM Role Has No Permissions Boundary",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_role",
        resource_id=result.role_arn,
        description=(
            f"IAM role '{result.role_name}' has a policy granting "
            f"privilege-management action "
            f"'{result.matching_action}' but has no permissions "
            f"boundary configured."
        ),
        evidence={
            "role_name": result.role_name,
            "role_arn": result.role_arn,
            "permissions_boundary": result.permissions_boundary,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "action": result.action,
            "matching_action": result.matching_action,
            "resource": result.resource,
            "permission_source": result.permission_source,
            "condition_present": bool(result.condition),
            "statement_index": result.statement_index,
        },
        remediation=(
            "Review whether the role requires privilege-management "
            "permissions. If delegated administration is intentional, "
            "consider applying an appropriate permissions boundary "
            "and restricting the delegated IAM actions."
        ),
        compliance=["CIS AWS Foundations"],
    )
