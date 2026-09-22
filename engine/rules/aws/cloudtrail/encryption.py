from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailEncryptionResult:
    trail_arn: str
    name: str | None
    kms_key_id: str | None


def check_cloudtrail_encryption(
    trail_arn: str,
    name: str | None,
    kms_key_id: str | None,
) -> CloudTrailEncryptionResult | None:
    """
    Detect a CloudTrail trail that is not configured
    with a KMS key for encryption.
    """
    if kms_key_id:
        return None

    return CloudTrailEncryptionResult(
        trail_arn=trail_arn,
        name=name,
        kms_key_id=None,
    )


def build_cloudtrail_encryption_finding(
    result: CloudTrailEncryptionResult,
) -> Finding:
    """
    Build a finding for a CloudTrail trail without
    a configured KMS key.
    """
    return Finding(
        rule_id="CS-AWS-CT-006",
        title="CloudTrail trail is not encrypted with a KMS key",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail",
        resource_id=result.trail_arn,
        description=(
            "The CloudTrail trail does not have a KMS key configured "
            "for log encryption. Using a customer-managed KMS key can "
            "provide additional control over encryption and access "
            "to CloudTrail log data."
        ),
        evidence={
            "trail_arn": result.trail_arn,
            "trail_name": result.name,
            "kms_key_id": result.kms_key_id,
        },
        remediation=(
            "Configure the CloudTrail trail to use an appropriate "
            "AWS KMS key for log encryption and ensure the key policy "
            "allows the required CloudTrail operations."
        ),
        compliance=["CIS AWS Foundations"],
    )
