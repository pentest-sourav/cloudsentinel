from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchDedicatedPrimaryNodesResult:
    domain_arn: str
    domain_name: str
    dedicated_master_enabled: bool
    dedicated_master_count: int | None
    cluster_config: dict[str, Any]


def check_opensearch_dedicated_primary_nodes(
    domain_arn: str,
    domain_name: str,
    cluster_config: dict[str, Any],
) -> OpenSearchDedicatedPrimaryNodesResult:
    if not isinstance(cluster_config, dict):
        cluster_config = {}

    dedicated_master_enabled = (
        cluster_config.get("DedicatedMasterEnabled") is True
    )

    dedicated_master_count = cluster_config.get(
        "DedicatedMasterCount"
    )

    if not isinstance(dedicated_master_count, int):
        dedicated_master_count = None

    return OpenSearchDedicatedPrimaryNodesResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        dedicated_master_enabled=dedicated_master_enabled,
        dedicated_master_count=dedicated_master_count,
        cluster_config=cluster_config,
    )


def build_opensearch_dedicated_primary_nodes_finding(
    result: OpenSearchDedicatedPrimaryNodesResult,
) -> Finding | None:
    if (
        result.dedicated_master_enabled
        and result.dedicated_master_count is not None
        and result.dedicated_master_count >= 3
    ):
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-011",
        title="OpenSearch Domain Does Not Have Three Dedicated Primary Nodes",
        severity=Severity.LOW,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "The OpenSearch domain does not have at least three "
            "dedicated primary nodes."
        ),
        evidence={
            "domain_name": result.domain_name,
            "dedicated_master_enabled": (
                result.dedicated_master_enabled
            ),
            "dedicated_master_count": (
                result.dedicated_master_count
            ),
            "cluster_config": result.cluster_config,
        },
        remediation=(
            "Configure the OpenSearch domain with at least three "
            "dedicated primary nodes."
        ),
        compliance=[
            "AWS Security Hub Opensearch.11",
        ],
    )
