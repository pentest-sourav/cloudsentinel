from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3VersioningResult:
    bucket_name: str
    versioning_enabled: bool
    status: str | None
    mfa_delete: str | None


def check_s3_versioning(
    bucket_name: str,
    versioning_status: dict,
) -> S3VersioningResult:
    status = versioning_status.get("Status")
    mfa_delete = versioning_status.get("MFADelete")

    versioning_enabled = status == "Enabled"

    return S3VersioningResult(
        bucket_name=bucket_name,
        versioning_enabled=versioning_enabled,
        status=status,
        mfa_delete=mfa_delete,
    )


def build_s3_versioning_finding(
    result: S3VersioningResult,
) -> Finding | None:
    if result.versioning_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-S3-005",
        title="S3 Bucket Versioning Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "S3 bucket versioning is not enabled. Without versioning, "
            "accidental deletion or overwriting of objects may reduce "
            "the ability to recover previous object versions."
        ),
        evidence={
            "versioning_enabled": result.versioning_enabled,
            "status": result.status,
            "mfa_delete": result.mfa_delete,
        },
        remediation=(
            "Enable S3 bucket versioning to retain previous versions "
            "of objects and improve recovery capability."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
