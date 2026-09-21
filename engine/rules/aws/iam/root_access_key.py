from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class RootAccessKeyResult:
    access_keys_present: bool


def check_root_access_key(
    access_keys_present: bool,
) -> RootAccessKeyResult:
    """
    Detect whether the AWS root account has an access key.

    Root access keys provide programmatic access with the highest
    level of account privilege and should not exist.
    """
    return RootAccessKeyResult(
        access_keys_present=access_keys_present,
    )


def build_root_access_key_finding(
    result: RootAccessKeyResult,
) -> Finding | None:
    if not result.access_keys_present:
        return None

    return Finding(
        rule_id="CS-AWS-IAM-021",
        title="AWS Root Account Access Key Exists",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="aws_account",
        resource_id="root",
        description=(
            "The AWS root account has one or more access keys. "
            "Root access keys provide programmatic access with "
            "full account privileges and should not exist."
        ),
        evidence={
            "access_keys_present": result.access_keys_present,
        },
        remediation=(
            "Remove all access keys associated with the AWS root "
            "account. Use IAM roles or other appropriate "
            "identity mechanisms for programmatic access instead."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
