from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class UserMFAResult:
    username: str
    mfa_enabled: bool
    reason: str


def check_user_mfa(
    username: str,
    mfa_devices: list[dict],
) -> UserMFAResult:
    mfa_enabled = len(mfa_devices) > 0

    if mfa_enabled:
        reason = (
            f"IAM user '{username}' has at least one MFA device."
        )
    else:
        reason = (
            f"IAM user '{username}' does not have an MFA device."
        )

    return UserMFAResult(
        username=username,
        mfa_enabled=mfa_enabled,
        reason=reason,
    )


def build_user_mfa_finding(
    result: UserMFAResult,
) -> Finding | None:
    if result.mfa_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-IAM-002",
        title="IAM User MFA Not Enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            "The IAM user does not have a multi-factor authentication "
            "device configured. Without MFA, compromise of the user's "
            "credentials can provide direct access to AWS resources "
            "allowed by that user's permissions."
        ),
        evidence={
            "username": result.username,
            "mfa_enabled": result.mfa_enabled,
            "mfa_device_count": 0,
            "reason": result.reason,
        },
        remediation=(
            "Enable MFA for the IAM user. Prefer stronger MFA methods "
            "where supported and enforce MFA for privileged or sensitive "
            "AWS access."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
