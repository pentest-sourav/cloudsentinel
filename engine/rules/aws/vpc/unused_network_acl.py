from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class UnusedNetworkACLResult:
    network_acl_id: str
    vpc_id: str | None
    association_count: int
    is_default: bool


def check_unused_network_acl(
    network_acl_id: str,
    vpc_id: str | None,
    association_count: int,
    is_default: bool,
) -> UnusedNetworkACLResult | None:
    if is_default:
        return None

    if association_count > 0:
        return None

    return UnusedNetworkACLResult(
        network_acl_id=network_acl_id,
        vpc_id=vpc_id,
        association_count=association_count,
        is_default=is_default,
    )


def build_unused_network_acl_finding(
    result: UnusedNetworkACLResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-009",
        title="Unused Network ACL should be removed",
        severity=Severity.LOW,
        provider="aws",
        resource_type="network_acl",
        resource_id=result.network_acl_id,
        description=(
            "The non-default Network ACL has no subnet associations. "
            "AWS Security Hub EC2.16 identifies unused Network ACLs "
            "for removal."
        ),
        evidence={
            "network_acl_id": result.network_acl_id,
            "vpc_id": result.vpc_id,
            "association_count": result.association_count,
            "is_default": result.is_default,
        },
        remediation=(
            "Remove the unused Network ACL if it is no longer required. "
            "Verify that it is not intended for future subnet association "
            "before deleting it."
        ),
        compliance=["AWS Security Hub EC2.16"],
    )
