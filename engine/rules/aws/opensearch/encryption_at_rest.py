from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchEncryptionAtRestResult:
    domain_arn: str
    domain_name: str
    encryption_enabled: bool
    encryption_options: dict[str, Any]


def check_opensearch_encryption_at_rest(
    domain_arn: str,
    domain_name: str,
    encryption_at_rest_options: dict[str, Any],
) -> OpenSearchEncryptionAtRestResult:
    if not isinstance(encryption_at_rest_options, dict):
        encryption_at_rest_options = {}

    enabled = (
        encryption_at_rest_options.get("Enabled") is True
    )

    return OpenSearchEncryptionAtRestResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        encryption_enabled=enabled,
        encryption_options=encryption_at_rest_options,
    )


def build_opensearch_encryption_at_rest_finding(
    result: OpenSearchEncryptionAtRestResult,
) -> Finding | None:
    if result.encryption_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-001",
        title="OpenSearch Domain Does Not Have Encryption At Rest Enabled",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "The OpenSearch domain does not have encryption "
            "at rest enabled."
        ),
        evidence={
            "domain_name": result.domain_name,
            "encryption_enabled": result.encryption_enabled,
            "encryption_options": result.encryption_options,
        },
        remediation=(
            "Enable encryption at rest for the OpenSearch domain."
        ),
        compliance=[
            "AWS Security Hub Opensearch.1",
        ],
    )
