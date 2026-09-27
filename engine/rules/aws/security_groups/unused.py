from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class UnusedSecurityGroupResult:
    group_id: str
    group_name: str | None
    attached_eni_count: int


def check_unused_security_group(
    group_id: str,
    group_name: str | None,
    attached_eni_count: int,
    is_default: bool,
) -> UnusedSecurityGroupResult | None:
    # Default Security Groups cannot be deleted, so they should not
    # produce an "unused and removable" finding.
    if is_default:
        return None

    if attached_eni_count != 0:
        return None

    return UnusedSecurityGroupResult(
        group_id=group_id,
        group_name=group_name,
        attached_eni_count=attached_eni_count,
    )


def build_unused_security_group_finding(
    result: UnusedSecurityGroupResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-SG-004",
        title="Unused Security Group should be removed",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="security_group",
        resource_id=result.group_id,
        description=(
            "The Security Group is not attached to any discovered "
            "Elastic Network Interface and is not the default group."
        ),
        evidence={
            "group_id": result.group_id,
            "group_name": result.group_name,
            "attached_eni_count": result.attached_eni_count,
        },
        remediation=(
            "Confirm that the Security Group is no longer required "
            "and remove it if it is unused."
        ),
        compliance=["AWS Security Hub"],
    )
