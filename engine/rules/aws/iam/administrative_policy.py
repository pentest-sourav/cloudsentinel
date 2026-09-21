from dataclasses import dataclass

from engine.findings.model import Finding, Severity


ADMINISTRATOR_POLICY_NAME = "AdministratorAccess"
ADMINISTRATOR_POLICY_ARN = (
    "arn:aws:iam::aws:policy/AdministratorAccess"
)


@dataclass(frozen=True)
class AdministrativeUserPolicyResult:
    username: str
    policy_name: str
    policy_arn: str | None
    policy_version_id: str | None


@dataclass(frozen=True)
class AdministrativeGroupPolicyResult:
    group_name: str
    policy_name: str
    policy_arn: str


def check_administrative_user_policy(
    username: str,
    policy_name: str | None,
    policy_arn: str | None,
    policy_version_id: str | None,
    effect: str | None,
    action: object,
    resource: object,
    condition: object,
) -> AdministrativeUserPolicyResult | None:
    """
    Detect AdministratorAccess attached directly to an IAM user.

    IAM-025 consumes the normalized managed-policy statement data
    already collected for IAM-012/IAM-016. This avoids introducing
    another list_attached_user_policies or list_user_policies call.

    The finding is intentionally limited to the AWS-managed
    AdministratorAccess policy. Custom policies that happen to
    provide administrative permissions remain covered by the
    broad-permission rules.
    """
    del action
    del resource
    del condition

    if effect != "Allow":
        return None

    if policy_name != ADMINISTRATOR_POLICY_NAME:
        return None

    if policy_arn != ADMINISTRATOR_POLICY_ARN:
        return None

    return AdministrativeUserPolicyResult(
        username=username,
        policy_name=policy_name,
        policy_arn=policy_arn,
        policy_version_id=policy_version_id,
    )


def build_administrative_user_policy_finding(
    result: AdministrativeUserPolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-025",
        title="AdministratorAccess Directly Attached to IAM User",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"The IAM user '{result.username}' has the AWS "
            "managed policy 'AdministratorAccess' directly "
            "attached."
        ),
        evidence={
            "username": result.username,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "policy_version_id": result.policy_version_id,
            "attachment_type": "direct_user_attachment",
        },
        remediation=(
            "Remove AdministratorAccess from the IAM user unless "
            "the user is explicitly designated and governed as an "
            "AWS administrator. Prefer role-based or group-based "
            "access with least-privilege permissions where "
            "possible."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )


def check_administrative_group_policy(
    group_name: str,
    policy_name: str | None,
    policy_arn: str | None,
) -> AdministrativeGroupPolicyResult | None:
    if policy_name != ADMINISTRATOR_POLICY_NAME:
        return None

    if policy_arn != ADMINISTRATOR_POLICY_ARN:
        return None

    return AdministrativeGroupPolicyResult(
        group_name=group_name,
        policy_name=policy_name,
        policy_arn=policy_arn,
    )


def build_administrative_group_policy_finding(
    result: AdministrativeGroupPolicyResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-026",
        title="AdministratorAccess Attached to IAM Group",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_group",
        resource_id=result.group_name,
        description=(
            f"The IAM group '{result.group_name}' has the AWS "
            "managed policy 'AdministratorAccess' directly "
            "attached."
        ),
        evidence={
            "group_name": result.group_name,
            "policy_name": result.policy_name,
            "policy_arn": result.policy_arn,
            "attachment_type": "direct_group_attachment",
        },
        remediation=(
            "Remove AdministratorAccess from the IAM group unless "
            "the group is explicitly governed as an administrator "
            "group. Prefer least-privilege policies and dedicated "
            "administrative roles where possible."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
