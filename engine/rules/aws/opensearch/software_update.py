from dataclasses import dataclass
from typing import Any

from engine.findings.model import Finding, Severity


@dataclass(frozen=True)
class OpenSearchSoftwareUpdateResult:
    domain_arn: str
    domain_name: str
    update_available: bool
    software_options: dict[str, Any]


def check_opensearch_software_update(
    domain_arn: str,
    domain_name: str,
    service_software_options: dict[str, Any],
) -> OpenSearchSoftwareUpdateResult:
    if not isinstance(service_software_options, dict):
        service_software_options = {}

    update_available = (
        service_software_options.get("UpdateAvailable") is True
    )

    return OpenSearchSoftwareUpdateResult(
        domain_arn=domain_arn,
        domain_name=domain_name,
        update_available=update_available,
        software_options=service_software_options,
    )


def build_opensearch_software_update_finding(
    result: OpenSearchSoftwareUpdateResult,
) -> Finding | None:
    if not result.update_available:
        return None

    return Finding(
        rule_id="CS-AWS-OPENSEARCH-010",
        title="OpenSearch Domain Has a Software Update Available",
        severity=Severity.MEDIUM,
        provider="aws",
        resource_type="opensearch_domain",
        resource_id=result.domain_arn,
        description=(
            "The OpenSearch domain has a software update available "
            "that has not been installed."
        ),
        evidence={
            "domain_name": result.domain_name,
            "update_available": result.update_available,
            "software_options": result.software_options,
        },
        remediation=(
            "Install the available OpenSearch service software update "
            "for the domain."
        ),
        compliance=[
            "AWS Security Hub Opensearch.10",
        ],
    )
