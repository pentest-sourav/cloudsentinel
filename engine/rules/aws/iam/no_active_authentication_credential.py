from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class NoActiveAuthenticationCredentialResult:
    username: str
    password_enabled: bool
    active_access_key_count: int
    active_access_key_ids: list[str]


def check_no_active_authentication_credential(
    username: str,
    password_enabled: bool,
    active_access_key_count: int,
    active_access_key_ids: list[str],
) -> NoActiveAuthenticationCredentialResult | None:
    """
    Detect an IAM user that has no active authentication credential.

    This is an identity-hygiene signal, not proof that the IAM user
    is unused. The user may still have permissions, group membership,
    or other organizational purposes.
    """
    if password_enabled:
        return None

    if active_access_key_count > 0:
        return None

    return NoActiveAuthenticationCredentialResult(
        username=username,
        password_enabled=password_enabled,
        active_access_key_count=active_access_key_count,
        active_access_key_ids=active_access_key_ids,
    )


def build_no_active_authentication_credential_finding(
    result: NoActiveAuthenticationCredentialResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-020",
        title="IAM User Has No Active Authentication Credential",
        severity=Severity.LOW,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"The IAM user '{result.username}' does not have an "
            "enabled console password or any active programmatic "
            "access key. This is an identity-hygiene signal and "
            "should be reviewed to determine whether the user is "
            "still required."
        ),
        evidence={
            "username": result.username,
            "password_enabled": result.password_enabled,
            "active_access_key_count": (
                result.active_access_key_count
            ),
            "active_access_key_ids": (
                result.active_access_key_ids
            ),
            "has_active_authentication_credential": False,
        },
        remediation=(
            "Review whether the IAM user is still required. If the "
            "identity is no longer needed, remove it according to "
            "your organization's identity lifecycle process. If the "
            "user is intentionally retained without active "
            "credentials, document its purpose and ownership."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
