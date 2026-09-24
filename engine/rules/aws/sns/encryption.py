from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SNSEncryptionResult:
    topic_arn: str
    encryption_enabled: bool
    kms_master_key_id: str | None


def check_sns_encryption(
    topic_arn: str,
    attributes: dict,
) -> SNSEncryptionResult:
    kms_master_key_id = attributes.get("KmsMasterKeyId")

    return SNSEncryptionResult(
        topic_arn=topic_arn,
        encryption_enabled=bool(kms_master_key_id),
        kms_master_key_id=kms_master_key_id,
    )


def build_sns_encryption_finding(
    result: SNSEncryptionResult,
) -> Finding | None:
    if result.encryption_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-SNS-002",
        title="SNS Topic Encryption Not Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="sns_topic",
        resource_id=result.topic_arn,
        description=(
            "The SNS topic does not have a customer-managed or "
            "AWS-managed KMS key configured for server-side encryption."
        ),
        evidence={
            "encryption_enabled": result.encryption_enabled,
            "kms_master_key_id": result.kms_master_key_id,
        },
        remediation=(
            "Configure server-side encryption for the SNS topic "
            "using an appropriate KMS key."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
