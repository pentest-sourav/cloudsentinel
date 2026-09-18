from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EBSEncryptionResult:
    """
    Result of evaluating the encryption state of an EBS volume
    attached to an EC2 instance.
    """

    instance_id: str
    volume_id: str
    encrypted: bool

    @property
    def is_unencrypted(self) -> bool:
        """Return True when the EBS volume is not encrypted."""

        return not self.encrypted


def check_ebs_encryption(
    instance_id: str,
    volume_id: str,
    encrypted: bool,
) -> EBSEncryptionResult | None:
    """
    Detect an EBS volume that is not encrypted.

    The rule only evaluates the normalized collector data.
    It does not perform AWS API calls or remediation.
    """

    if encrypted:
        return None

    return EBSEncryptionResult(
        instance_id=instance_id,
        volume_id=volume_id,
        encrypted=encrypted,
    )


def build_ebs_encryption_finding(
    result: EBSEncryptionResult,
) -> Finding:
    """
    Convert an unencrypted EBS volume result into a CloudSentinel
    security finding with evidence and remediation guidance.
    """

    return Finding(
        rule_id="CS-AWS-EC2-004",
        title="EBS Volume Is Not Encrypted",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="ebs_volume",
        resource_id=result.volume_id,
        description=(
            f"The EBS volume {result.volume_id}, attached to "
            f"EC2 instance {result.instance_id}, is not encrypted. "
            "Data stored on an unencrypted EBS volume is not protected "
            "by EBS encryption at rest."
        ),
        evidence={
            "instance_id": result.instance_id,
            "volume_id": result.volume_id,
            "encrypted": result.encrypted,
            "encryption_status": "unencrypted",
        },
        remediation=(
            "Use encrypted EBS volumes for workloads that require "
            "encryption at rest. For an existing unencrypted volume, "
            "create an encrypted snapshot or encrypted replacement "
            "volume and migrate the workload according to the "
            "workload's availability and change-management requirements."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
