from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class MultipleActiveAccessKeysResult:
    username: str
    active_access_key_count: int
    active_access_key_ids: list[str]


def check_multiple_active_access_keys(
    username: str,
    active_access_key_count: int,
    active_access_key_ids: list[str],
) -> MultipleActiveAccessKeysResult | None:
    if active_access_key_count <= 1:
        return None

    return MultipleActiveAccessKeysResult(
        username=username,
        active_access_key_count=active_access_key_count,
        active_access_key_ids=active_access_key_ids,
    )


def build_multiple_active_access_keys_finding(
    result: MultipleActiveAccessKeysResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-IAM-017",
        title="IAM User Has Multiple Active Access Keys",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="iam_user",
        resource_id=result.username,
        description=(
            f"The IAM user '{result.username}' has "
            f"{result.active_access_key_count} active access keys. "
            "Multiple simultaneously active long-lived credentials "
            "increase the credential attack surface and should be "
            "reviewed for necessity."
        ),
        evidence={
            "username": result.username,
            "active_access_key_count": (
                result.active_access_key_count
            ),
            "active_access_key_ids": result.active_access_key_ids,
        },
        remediation=(
            "Review the active access keys for the IAM user and "
            "retain only the credentials required by legitimate "
            "workloads. Rotate and remove unnecessary keys after "
            "verifying application dependencies."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
