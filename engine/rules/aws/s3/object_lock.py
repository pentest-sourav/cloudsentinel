from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3ObjectLockResult:
    bucket_name: str
    object_lock_enabled: bool
    configuration: dict


def check_s3_object_lock(
    bucket_name: str,
    object_lock_configuration: dict,
) -> S3ObjectLockResult:
    object_lock_enabled = (
        object_lock_configuration.get("ObjectLockEnabled")
        == "Enabled"
    )

    return S3ObjectLockResult(
        bucket_name=bucket_name,
        object_lock_enabled=object_lock_enabled,
        configuration=object_lock_configuration,
    )


def build_s3_object_lock_finding(
    result: S3ObjectLockResult,
) -> Finding | None:
    if result.object_lock_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-S3-007",
        title="S3 Object Lock Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "S3 Object Lock is not enabled for the bucket. "
            "Without Object Lock, objects do not have the additional "
            "write-once-read-many protection that can help prevent "
            "objects from being deleted or overwritten during their "
            "retention period."
        ),
        evidence={
            "object_lock_enabled": result.object_lock_enabled,
            "configuration": result.configuration,
        },
        remediation=(
            "Enable S3 Object Lock when immutable object retention "
            "is required. Define an appropriate retention mode and "
            "retention period based on the data protection requirements."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
