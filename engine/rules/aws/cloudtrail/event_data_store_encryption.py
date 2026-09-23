from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class CloudTrailEventDataStoreEncryptionResult:
    event_data_store_arn: str
    name: str | None
    kms_key_id: str | None

    @property
    def encrypted_with_customer_managed_key(self) -> bool:
        return bool(self.kms_key_id)


def check_cloudtrail_event_data_store_encryption(
    event_data_store_arn: str,
    name: str | None,
    kms_key_id: str | None,
) -> CloudTrailEventDataStoreEncryptionResult:
    """
    Evaluate whether a CloudTrail Lake event data store uses
    a customer-managed KMS key.
    """
    return CloudTrailEventDataStoreEncryptionResult(
        event_data_store_arn=event_data_store_arn,
        name=name,
        kms_key_id=kms_key_id,
    )


def build_cloudtrail_event_data_store_encryption_finding(
    result: CloudTrailEventDataStoreEncryptionResult,
) -> Finding | None:
    if result.encrypted_with_customer_managed_key:
        return None

    return Finding(
        rule_id="CS-AWS-CT-010",
        title=(
            "CloudTrail Lake event data store is not encrypted "
            "with a customer-managed KMS key"
        ),
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="cloudtrail_event_data_store",
        resource_id=result.event_data_store_arn,
        description=(
            "The CloudTrail Lake event data store is not configured "
            "with a customer-managed AWS KMS key. CloudTrail "
            "otherwise uses AWS-managed encryption for the event "
            "data store."
        ),
        evidence={
            "event_data_store_arn": result.event_data_store_arn,
            "event_data_store_name": result.name,
            "kms_key_id": result.kms_key_id,
            "customer_managed_kms_encryption": (
                result.encrypted_with_customer_managed_key
            ),
        },
        remediation=(
            "Configure the CloudTrail Lake event data store to use "
            "an appropriate customer-managed AWS KMS key and "
            "ensure the KMS key policy permits CloudTrail to "
            "encrypt the event data store."
        ),
        compliance=[
            "NIST SP 800-53 Rev. 5",
        ],
    )
