from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity
from engine.rules.aws.iam.policy_scope import (
    first_matching_action,
    has_wildcard_resource,
)


SENSITIVE_CREDENTIAL_ACTIONS = {
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "iam:UpdateAccessKey",
    "iam:CreateVirtualMFADevice",
    "iam:DeactivateMFADevice",
}


@dataclass(frozen=True)
class SensitiveCredentialActionResult:
    permission_source: str
    resource_id: str
    principal_type: str
    principal_id: str
    username: str | None
    group_name: str | None
    policy_name: str
    policy_arn: str | None
    policy_version_id: str | None
    statement_index: int | None
    effect: str
    action: str
    resource: Any
    condition: Any


def check_sensitive_credential_action(
    permission_source: str,
    resource_id: str,
    principal_type: str,
    principal_id: str,
    username: str | None,
    group_name: str | None,
    policy_name: str,
    policy_arn: str | None,
    policy_version_id: str | None,
    statement_index: int | None,
    effect: str | None,
    action: Any,
    resource: Any,
    condition: Any,
) -> SensitiveCredentialActionResult | None:
    if effect != "Allow":
        return None

    if not has_wildcard_resource(resource):
        return None

    matched_action = first_matching_action(
        action,
        SENSITIVE_CREDENTIAL_ACTIONS,
    )

    if matched_action is None:
        return None

    return SensitiveCredentialActionResult(
        permission_source=permission_source,
        resource_id=resource_id,
        principal_type=principal_type,
        principal_id=principal_id,
        username=username,
        group_name=group_name,
        policy_name=policy_name,
        policy_arn=policy_arn,
        policy_version_id=policy_version_id,
        statement_index=statement_index,
        effect=effect,
        action=matched_action,
        resource=resource,
        condition=condition,
    )


def build_sensitive_credential_action_finding(
    result: SensitiveCredentialActionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-024",
        title="Sensitive IAM Credential Action Uses Wildcard Resource",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_identity",
        resource_id=result.resource_id,
        description=(
            f"The IAM {result.principal_type} "
            f"'{result.principal_id}' is allowed to perform "
            f"'{result.action}' against all IAM resources."
        ),
        evidence={
            "permission_source": result.permission_source,
            "principal_type": result.principal_type,
            "principal_id": result.principal_id,
            "username": result.username,
            "group_name": result.group_name,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "policy_version_id": result.policy_version_id,
            "statement_index": result.statement_index,
            "effect": result.effect,
            "action": result.action,
            "resource": result.resource,
            "condition": result.condition,
        },
        remediation=(
            "Restrict sensitive credential-management actions to "
            "the specific IAM resources that require them. Review "
            "whether the principal needs the permission at all and "
            "remove account-wide wildcard resource access where "
            "possible."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
