from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RootMFAResult:
    mfa_enabled: bool
    reason: str


def check_root_mfa(
    root_mfa_enabled: bool,
) -> RootMFAResult:
    if root_mfa_enabled:
        return RootMFAResult(
            mfa_enabled=True,
            reason="Root account MFA is enabled.",
        )

    return RootMFAResult(
        mfa_enabled=False,
        reason="Root account MFA is not enabled.",
    )


def build_root_mfa_finding(
    result: RootMFAResult,
) -> Finding | None:
    if result.mfa_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-IAM-001",
        title="AWS Root Account MFA Not Enabled",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="aws_account",
        resource_id="root",
        description=(
            "Multi-factor authentication is not enabled for the "
            "AWS root account. The root account has highly privileged "
            "access and should be protected with MFA."
        ),
        evidence={
            "mfa_enabled": result.mfa_enabled,
            "reason": result.reason,
        },
        remediation=(
            "Enable MFA for the AWS root account and use the root "
            "account only for tasks that specifically require it."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
