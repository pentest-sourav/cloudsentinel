from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchFineGrainedAccessResult:
    domain_arn: str
    domain_name: str
    access_control_enabled: bool
    advanced_security_options: dict[str, Any]


def check_opensearch_fine_grained_access_control(
    domain_arn: str,
    domain_name: str,
    advanced_security_options: dict[str, Any],
) -> OpenSearchFineGrainedAccessResult:
    if not isinstance(advanced_security_options, dict):
        advanced_security_options = {}

    enabled = (
        advanced_security_options.get("Enabled") is True
    )

    return OpenSearchFineGrainedAccessResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        access_control_enabled=enabled,
        advanced_security_options=advanced_security_options,
    )


def build_opensearch_fine_grained_access_control_finding(
    result: OpenSearchFineGrainedAccessResult,
) -> Finding | None:
    if result.access_control_enabled:
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-007",
        title="OpenSearch Fine-Grained Access Control Is Not Enabled",
        severity=Severity.HIGH,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "Fine-grained access control is not enabled for "
            "the OpenSearch domain."
        ),
        evidence={
            "domain_name": result.domain_name,
            "access_control_enabled": (
                result.access_control_enabled
            ),
            "advanced_security_options": (
                result.advanced_security_options
            ),
        },
        remediation=(
            "Enable fine-grained access control for the "
            "OpenSearch domain."
        ),
        compliance=[
            "AWS Security Hub Opensearch.7",
        ],
    )
