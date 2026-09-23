from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class EBSDefaultEncryptionResult:
    """
    Result of evaluating regional EBS encryption-by-default.
    """

    enabled: bool


def check_ebs_default_encryption(
    ebs_encryption_by_default: bool,
) -> EBSDefaultEncryptionResult | None:
    """
    Detect when EBS encryption by default is disabled.
    """

    if ebs_encryption_by_default:
        return None

    return EBSDefaultEncryptionResult(
        enabled=False,
    )


def build_ebs_default_encryption_finding(
    result: EBSDefaultEncryptionResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-006",
        title="EBS Encryption by Default Is Disabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="aws_ec2_region",
        resource_id="regional-ebs-encryption",
        description=(
            "EBS encryption by default is disabled in the "
            "current AWS region. New EBS volumes can therefore "
            "be created without encryption unless encryption "
            "is explicitly requested."
        ),
        evidence={
            "ebs_encryption_by_default": result.enabled,
        },
        remediation=(
            "Enable EBS encryption by default for the AWS region. "
            "Continue reviewing existing EBS volumes separately "
            "because enabling the regional default does not "
            "retroactively encrypt existing unencrypted volumes."
        ),
        compliance=[
            "AWS Security Hub EC2.7",
            "CIS AWS Foundations Benchmark v5.0.0 / 5.1.1",
        ],
    )
