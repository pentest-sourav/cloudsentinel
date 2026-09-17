from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EBSEncryptionResult:
    """
    Result of detecting an unencrypted EBS volume
    attached to an EC2 instance.
    """

    instance_id: str
    volume_id: str
    encrypted: bool

    @property
    def is_unencrypted(self) -> bool:
        return not self.encrypted


def check_ebs_encryption(
    instance_id: str,
    volume_id: str,
    encrypted: bool,
) -> EBSEncryptionResult | None:
    """
    Detect an EBS volume that is not encrypted.
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
    Convert an unencrypted EBS volume result
    into a CloudSentinel Finding.
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
            "Unencrypted volumes may expose stored data if the "
            "underlying storage is accessed outside the intended "
            "security boundary."
        ),
        evidence={
            "instance_id": result.instance_id,
            "volume_id": result.volume_id,
            "encrypted": result.encrypted,
        },
        remediation=(
            "Use encrypted EBS volumes for sensitive workloads. "
            "For existing unencrypted volumes, create an encrypted "
            "snapshot or encrypted replacement volume and migrate "
            "the workload as appropriate."
        ),
        compliance=[
            "CIS AWS Foundations",
        ],
    )
