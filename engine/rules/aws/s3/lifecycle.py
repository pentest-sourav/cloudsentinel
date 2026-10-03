from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3LifecycleResult:
    bucket_name: str
    versioning_enabled: bool
    lifecycle_configured: bool
    lifecycle_configuration: dict[str, Any]


def check_s3_lifecycle(
    bucket_name: str,
    versioning_status: dict,
    lifecycle_configuration: dict,
) -> S3LifecycleResult:
    versioning_enabled = versioning_status.get("Status") == "Enabled"

    rules = lifecycle_configuration.get("Rules", [])
    lifecycle_configured = isinstance(rules, list) and bool(rules)

    return S3LifecycleResult(
        bucket_name=bucket_name,
        versioning_enabled=versioning_enabled,
        lifecycle_configured=lifecycle_configured,
        lifecycle_configuration=lifecycle_configuration,
    )


def build_s3_lifecycle_finding(
    result: S3LifecycleResult,
) -> Finding | None:
    if not result.versioning_enabled or result.lifecycle_configured:
        return None

    return Finding(
        rule_id="CS-AWS-S3-010",
        title="Versioned S3 Bucket Has No Lifecycle Configuration",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket has versioning enabled but no active Lifecycle "
            "configuration. Retained object versions can grow without "
            "bounded retention or transition policies."
        ),
        evidence={
            "versioning_enabled": result.versioning_enabled,
            "lifecycle_configured": result.lifecycle_configured,
            "lifecycle_configuration": result.lifecycle_configuration,
        },
        remediation=(
            "Configure an S3 Lifecycle policy for the versioned bucket, "
            "including appropriate transitions or expiration for current "
            "and noncurrent object versions."
        ),
        compliance=[
            "AWS Security Hub S3.10",
        ],
    )
