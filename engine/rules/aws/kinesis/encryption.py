from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class KinesisEncryptionResult:
    resource_id: str
    expected_configuration: str
    actual_configuration: str


def check_kinesis_encryption(
    stream_arn: str,
    encryption_type: str | None,
) -> KinesisEncryptionResult | None:
    if encryption_type == "KMS":
        return None

    return KinesisEncryptionResult(
        resource_id=stream_arn,
        expected_configuration="KMS",
        actual_configuration=(
            encryption_type
            if encryption_type is not None
            else "MISSING"
        ),
    )


def build_kinesis_encryption_finding(
    result: KinesisEncryptionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-KINESIS-001",
        title="Kinesis streams should be encrypted at rest",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="kinesis_stream",
        resource_id=result.resource_id,
        description=(
            "The Kinesis stream is not encrypted at rest "
            "with server-side encryption."
        ),
        evidence={
            "stream_arn": result.resource_id,
            "expected_configuration": (
                result.expected_configuration
            ),
            "actual_configuration": (
                result.actual_configuration
            ),
        },
        remediation=(
            "Enable server-side encryption for the "
            "Kinesis stream using KMS."
        ),
        compliance=[
            "AWS Security Hub Kinesis.1",
        ],
    )
