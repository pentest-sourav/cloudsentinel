from dataclasses import dataclass

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class DefaultSecurityGroupResult:
    group_id: str
    vpc_id: str
    inbound_rule_count: int
    outbound_rule_count: int


def check_default_security_group(
    group_id: str,
    vpc_id: str,
    group_name: str | None,
    inbound_rule_count: int,
    outbound_rule_count: int,
) -> DefaultSecurityGroupResult | None:
    if inbound_rule_count == 0 and outbound_rule_count == 0:
        return None

    return DefaultSecurityGroupResult(
        group_id=group_id,
        vpc_id=vpc_id,
        inbound_rule_count=inbound_rule_count,
        outbound_rule_count=outbound_rule_count,
    )


def build_default_security_group_finding(
    result: DefaultSecurityGroupResult,
) -> Finding:
    return Finding(
        rule_id="CS-AWS-VPC-003",
        title="Default Security Group allows traffic",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="security_group",
        resource_id=result.group_id,
        description=(
            "The VPC default Security Group contains inbound or outbound "
            "rules. AWS recommends restricting both directions on default "
            "Security Groups to prevent unintended traffic."
        ),
        evidence={
            "group_id": result.group_id,
            "vpc_id": result.vpc_id,
            "inbound_rule_count": result.inbound_rule_count,
            "outbound_rule_count": result.outbound_rule_count,
        },
        remediation=(
            "Create and use purpose-specific least-privilege Security Groups, "
            "then remove unnecessary inbound and outbound rules from the "
            "default Security Group."
        ),
        compliance=[
            "CIS AWS Foundations Benchmark v5.0.0 / EC2.2",
        ],
    )
