from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class S3KMSEncryptionResult:
    bucket_name: str
    encrypted_with_kms: bool
    algorithm: str | None
    kms_master_key_id: str | None
    configuration: dict[str, Any]


def check_s3_kms_encryption(
    bucket_name: str,
    encryption_configuration: dict[str, Any],
) -> S3KMSEncryptionResult:
    rules = encryption_configuration.get("Rules", [])

    if not isinstance(rules, list):
        rules = []

    default_encryption: dict[str, Any] = {}

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        candidate = rule.get("ApplyServerSideEncryptionByDefault")

        if isinstance(candidate, dict):
            default_encryption = candidate
            break

    algorithm = default_encryption.get("SSEAlgorithm")
    kms_master_key_id = default_encryption.get("KMSMasterKeyID")

    encrypted_with_kms = algorithm == "aws:kms"

    return S3KMSEncryptionResult(
        bucket_name=bucket_name,
        encrypted_with_kms=encrypted_with_kms,
        algorithm=algorithm,
        kms_master_key_id=kms_master_key_id,
        configuration=encryption_configuration,
    )


def build_s3_kms_encryption_finding(
    result: S3KMSEncryptionResult,
) -> Finding | None:
    if result.encrypted_with_kms:
        return None

    return Finding(
        rule_id="CS-AWS-S3-017",
        title="S3 Bucket Not Encrypted With AWS KMS",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="s3_bucket",
        resource_id=result.bucket_name,
        description=(
            "The S3 bucket does not use AWS KMS server-side encryption "
            "for its default bucket encryption configuration. "
            "AWS KMS encryption provides key-based controls and auditability "
            "beyond generic server-side encryption."
        ),
        evidence={
            "encrypted_with_kms": result.encrypted_with_kms,
            "algorithm": result.algorithm,
            "kms_master_key_id": result.kms_master_key_id,
            "configuration": result.configuration,
        },
        remediation=(
            "Configure the S3 bucket's default server-side encryption "
            "to use AWS KMS (aws:kms) and specify an appropriate KMS key."
        ),
        compliance=[
            "AWS Security Hub S3.17",
            "NIST SP 800-53 Rev. 5",
            "NIST SP 800-171 Rev. 2",
            "PCI DSS v4.0.1",
        ],
    )
