from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class ParavirtualResult:
    """
    Result of evaluating an EC2 virtualization type.
    """

    instance_id: str
    virtualization_type: str


def check_paravirtual(
    instance_id: str,
    virtualization_type: str | None,
) -> ParavirtualResult | None:
    """
    Detect EC2 instances using paravirtual virtualization.
    """

    if not virtualization_type:
        return None

    if virtualization_type.lower() != "paravirtual":
        return None

    return ParavirtualResult(
        instance_id=instance_id,
        virtualization_type=virtualization_type,
    )


def build_paravirtual_finding(
    result: ParavirtualResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-EC2-009",
        title="EC2 Instance Uses Paravirtual Virtualization",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="ec2_instance",
        resource_id=result.instance_id,
        description=(
            f"The EC2 instance {result.instance_id} uses "
            "paravirtual virtualization. AWS recommends using "
            "hardware virtual machine (HVM) virtualization for "
            "modern EC2 workloads."
        ),
        evidence={
            "instance_id": result.instance_id,
            "virtualization_type": (
                result.virtualization_type
            ),
        },
        remediation=(
            "Migrate the workload to an HVM-compatible AMI and "
            "instance configuration. Validate application "
            "compatibility before replacing the existing instance."
        ),
        compliance=[
            "AWS Security Hub EC2.24",
        ],
    )
