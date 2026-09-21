from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class UserAttachedPolicyResult:
    username: str
    managed_policy_count: int
    managed_policy_names: list[str]
    inline_policy_count: int
    inline_policy_names: list[str]

    @property
    def has_attached_policies(self) -> bool:
        return (
            self.managed_policy_count > 0
            or self.inline_policy_count > 0
        )


def check_user_attached_policy(
    username: str,
    managed_policy_count: int,
    managed_policy_names: list[str],
    inline_policy_count: int,
    inline_policy_names: list[str],
) -> UserAttachedPolicyResult:
    """
    Detect whether an IAM user has policies attached directly.

    Both customer/AWS-managed policies attached to the user and
    inline policies embedded in the user are evaluated.
    """
    return UserAttachedPolicyResult(
        username=username,
        managed_policy_count=managed_policy_count,
        managed_policy_names=managed_policy_names,
        inline_policy_count=inline_policy_count,
        inline_policy_names=inline_policy_names,
    )


def build_user_attached_policy_finding(
    result: UserAttachedPolicyResult,
) -> Finding | None:
    if not result.has_attached_policies:
        return None

    return Finding(
        rule_id="CS-AWS-IAM-022",
        title="IAM User Has Policies Attached Directly",
        severity=Severity.LOW,
        provider="aws",
        resource_type="aws_iam_user",
        resource_id=result.username,
        description=(
            f"IAM user '{result.username}' has one or more "
            "policies attached directly. IAM users should "
            "inherit permissions through groups or assume "
            "roles instead of receiving policies directly."
        ),
        evidence={
            "managed_policy_count": (
                result.managed_policy_count
            ),
            "managed_policy_names": (
                result.managed_policy_names
            ),
            "inline_policy_count": (
                result.inline_policy_count
            ),
            "inline_policy_names": (
                result.inline_policy_names
            ),
        },
        remediation=(
            "Remove policies attached directly to the IAM user. "
            "Attach the required policies to an appropriate IAM "
            "group and add the user to that group, or use an IAM "
            "role where appropriate."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
