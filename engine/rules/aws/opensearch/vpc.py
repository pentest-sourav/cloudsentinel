from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchVPCResult:
    domain_arn: str
    domain_name: str
    vpc_enabled: bool
    vpc_options: dict[str, Any]


def check_opensearch_vpc(
    domain_arn: str,
    domain_name: str,
    vpc_options: dict[str, Any],
) -> OpenSearchVPCResult:
    if not isinstance(vpc_options, dict):
        vpc_options = {}

    vpc_id = vpc_options.get("VPCId")

    enabled = (
        isinstance(vpc_id, str)
        and bool(vpc_id)
    )

    return OpenSearchVPCResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        vpc_enabled=enabled,
        vpc_options=vpc_options,
    )


def build_opensearch_vpc_finding(
    result: OpenSearchVPCResult,
) -> Finding | None:
    if result.vpc_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-002",
        title="OpenSearch Domain Is Not Deployed In A VPC",
        severity=Severity.CRITICAL,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "The OpenSearch domain is not configured within "
            "an Amazon VPC."
        ),
        evidence={
            "domain_name": result.domain_name,
            "vpc_enabled": result.vpc_enabled,
            "vpc_options": result.vpc_options,
        },
        remediation=(
            "Deploy the OpenSearch domain within a VPC. "
            "A public domain cannot be converted to a VPC domain "
            "in place."
        ),
        compliance=[
            "AWS Security Hub Opensearch.2",
        ],
    )
