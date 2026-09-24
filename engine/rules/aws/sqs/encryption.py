from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class SQSEncryptionResult:
    queue_arn: str
    encryption_enabled: bool
    encryption_type: str | None
    kms_master_key_id: str | None


def check_sqs_encryption(
    queue_arn: str,
    kms_master_key_id: str | None,
    sqs_managed_sse_enabled: str | None,
) -> SQSEncryptionResult:
    if kms_master_key_id:
        encryption_type = "SSE-KMS"
    elif str(sqs_managed_sse_enabled).lower() == "true":
        encryption_type = "SSE-SQS"
    else:
        encryption_type = None

    return SQSEncryptionResult(
        queue_arn=queue_arn,
        encryption_enabled=encryption_type is not None,
        encryption_type=encryption_type,
        kms_master_key_id=kms_master_key_id,
    )


def build_sqs_encryption_finding(
    result: SQSEncryptionResult,
) -> Finding | None:
    if result.encryption_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-SQS-001",
        title="SQS Queue Is Not Encrypted At Rest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="sqs_queue",
        resource_id=result.queue_arn,
        description=(
            "The SQS queue is not configured with server-side "
            "encryption using either SSE-SQS or SSE-KMS."
        ),
        evidence={
            "encryption_enabled": result.encryption_enabled,
            "encryption_type": result.encryption_type,
            "kms_master_key_id": result.kms_master_key_id,
        },
        remediation=(
            "Enable server-side encryption for the SQS queue using "
            "SSE-SQS or SSE-KMS."
        ),
        compliance=[
            "AWS Security Hub SQS.1",
        ],
    )
