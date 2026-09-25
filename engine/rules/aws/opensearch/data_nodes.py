from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchDataNodesResult:
    domain_arn: str
    domain_name: str
    instance_count: int | None
    zone_awareness_enabled: bool
    cluster_config: dict[str, Any]


def check_opensearch_data_nodes(
    domain_arn: str,
    domain_name: str,
    cluster_config: dict[str, Any],
) -> OpenSearchDataNodesResult:
    if not isinstance(cluster_config, dict):
        cluster_config = {}

    instance_count = cluster_config.get(
        "InstanceCount"
    )

    if not isinstance(instance_count, int):
        instance_count = None

    zone_awareness_enabled = (
        cluster_config.get("ZoneAwarenessEnabled") is True
    )

    return OpenSearchDataNodesResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        instance_count=instance_count,
        zone_awareness_enabled=zone_awareness_enabled,
        cluster_config=cluster_config,
    )


def build_opensearch_data_nodes_finding(
    result: OpenSearchDataNodesResult,
) -> Finding | None:
    if (
        result.instance_count is not None
        and result.instance_count >= 3
        and result.zone_awareness_enabled
    ):
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-006",
        title="OpenSearch Domain Does Not Have Three Data Nodes With Zone Awareness",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "The OpenSearch domain does not have at least three "
            "data nodes with zone awareness enabled."
        ),
        evidence={
            "domain_name": result.domain_name,
            "instance_count": result.instance_count,
            "zone_awareness_enabled": (
                result.zone_awareness_enabled
            ),
            "cluster_config": result.cluster_config,
        },
        remediation=(
            "Configure at least three data nodes and enable "
            "zone awareness for the OpenSearch domain."
        ),
        compliance=[
            "AWS Security Hub Opensearch.6",
        ],
    )
