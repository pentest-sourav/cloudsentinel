from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3EncryptionResult:
    bucket_name: str
    encryption_enabled: bool
    algorithm: str | None
    configuration: dict


def check_s3_encryption(
    bucket_name: str,
    encryption_configuration: dict,
) -> S3EncryptionResult:
    rules = encryption_configuration.get("Rules", [])

    if not rules:
        return S3EncryptionResult(
            bucket_name=bucket_name,
            encryption_enabled=False,
            algorithm=None,
            configuration=encryption_configuration,
        )

    default_encryption = rules[0].get(
        "ApplyServerSideEncryptionByDefault",
        {},
    )

    algorithm = default_encryption.get("SSEAlgorithm")

    return S3EncryptionResult(
        bucket_name=bucket_name,
        encryption_enabled=algorithm is not None,
        algorithm=algorithm,
        configuration=encryption_configuration,
    )


def build_s3_encryption_finding(
    result: S3EncryptionResult,
) -> Finding | None:
    if result.encryption_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-S3-002",
        title="S3 Bucket Default Encryption Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket does not have a default server-side "
            "encryption configuration."
        ),
        evidence={
            "encryption_enabled": result.encryption_enabled,
            "algorithm": result.algorithm,
            "configuration": result.configuration,
        },
        remediation=(
            "Enable default server-side encryption for the S3 bucket."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
