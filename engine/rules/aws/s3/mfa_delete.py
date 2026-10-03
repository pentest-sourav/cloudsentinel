from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3MFADelResult:
    bucket_name: str
    versioning_enabled: bool
    mfa_delete_enabled: bool
    status: str | None


def check_s3_mfa_delete(
    bucket_name: str,
    versioning_status: dict[str, Any],
) -> S3MFADelResult:
    status = versioning_status.get("Status")
    mfa_delete = versioning_status.get("MFADelete")

    return S3MFADelResult(
        bucket_name=bucket_name,
        versioning_enabled=status == "Enabled",
        mfa_delete_enabled=mfa_delete == "Enabled",
        status=status,
    )


def build_s3_mfa_delete_finding(
    result: S3MFADelResult,
) -> Finding | None:
    if not result.versioning_enabled or result.mfa_delete_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-S3-020",
        title="S3 Bucket MFA Delete Not Enabled",
        severity=Severity.LOW,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "S3 bucket versioning is enabled but MFA Delete is not enabled. "
            "MFA Delete adds an additional authentication requirement for "
            "deleting object versions."
        ),
        evidence={
            "versioning_enabled": result.versioning_enabled,
            "mfa_delete_enabled": result.mfa_delete_enabled,
            "status": result.status,
        },
        remediation=(
            "Enable MFA Delete for the versioned S3 bucket where supported "
            "and operationally appropriate."
        ),
        compliance=[
            "AWS Security Hub S3.20",
            "CIS AWS Foundations",
        ],
    )
