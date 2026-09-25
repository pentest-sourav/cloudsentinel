from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchNodeToNodeEncryptionResult:
    domain_arn: str
    domain_name: str
    encryption_enabled: bool
    encryption_options: dict[str, Any]


def check_opensearch_node_to_node_encryption(
    domain_arn: str,
    domain_name: str,
    node_to_node_encryption_options: dict[str, Any],
) -> OpenSearchNodeToNodeEncryptionResult:
    if not isinstance(node_to_node_encryption_options, dict):
        node_to_node_encryption_options = {}

    enabled = (
        node_to_node_encryption_options.get("Enabled") is True
    )

    return OpenSearchNodeToNodeEncryptionResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        encryption_enabled=enabled,
        encryption_options=node_to_node_encryption_options,
    )


def build_opensearch_node_to_node_encryption_finding(
    result: OpenSearchNodeToNodeEncryptionResult,
) -> Finding | None:
    if result.encryption_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-003",
        title="OpenSearch Domain Does Not Encrypt Node-to-Node Traffic",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "Node-to-node encryption is not enabled for the "
            "OpenSearch domain."
        ),
        evidence={
            "domain_name": result.domain_name,
            "encryption_enabled": result.encryption_enabled,
            "encryption_options": result.encryption_options,
        },
        remediation=(
            "Enable node-to-node encryption for the OpenSearch domain."
        ),
        compliance=[
            "AWS Security Hub Opensearch.3",
        ],
    )
