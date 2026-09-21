from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class MultipleAuthenticationMethodsResult:
    username: str
    password_enabled: bool
    active_access_key_count: int
    active_access_key_ids: list[str]


def check_multiple_authentication_methods(
    username: str,
    password_enabled: bool,
    active_access_key_count: int,
    active_access_key_ids: list[str],
) -> MultipleAuthenticationMethodsResult | None:
    if not password_enabled:
        return None

    if active_access_key_count <= 0:
        return None

    return MultipleAuthenticationMethodsResult(
        username=username,
        password_enabled=password_enabled,
        active_access_key_count=active_access_key_count,
        active_access_key_ids=active_access_key_ids,
    )


def build_multiple_authentication_methods_finding(
    result: MultipleAuthenticationMethodsResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-018",
        title="IAM User Has Multiple Authentication Methods",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"The IAM user '{result.username}' has both an "
            "enabled console password and one or more active "
            "programmatic access keys. Multiple authentication "
            "methods increase the user's credential attack surface "
            "and should be reviewed for necessity."
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
        },
        remediation=(
            "Review whether both console and programmatic access "
            "are required for this IAM user. Remove unnecessary "
            "authentication methods and prefer separate identities "
            "for distinct workloads or access requirements."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
